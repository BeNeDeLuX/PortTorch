import { Router } from "express";
import { z } from "zod";
import { sql } from "kysely";
import { db } from "../db";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestRescan } from "../rescan";
import { requestScanCancel } from "../scanCancel";
import { tokenAuth } from "../apiTokens/tokenAuth";
import { zIp } from "../lib/zodIp";
import { applyHostFilters, parseHostFilterParams } from "../search/routes";
import { ScanProfileNotFoundError, resolveNSEProfile, type NSEProfileSelection } from "../scanProfiles/resolve";
import { NucleiProfileNotFoundError, resolveNucleiProfile, type NucleiProfileSelection } from "../nucleiProfiles/resolve";

// External, non-interactive API for SOAR/enrichment tools - token auth
// (tokenAuth), not session auth or scanner API keys. Kept as its own
// router/path (/api/v1) rather than bolted onto the dashboard's /api/hosts
// routes, since those assume an interactive session throughout (RBAC role
// checks, req.session.username for audit attribution) and this has a
// narrower, stable surface: look a host up by ip/hostname, trigger a
// rescan of it, or queue a one-shot scan against a target that isn't a
// known host yet (POST /scans/adhoc below - the External API counterpart
// to the dashboard's own Ad-hoc Scans page, for the case a SOAR tool
// needs to scan something it just learned about from outside this app
// entirely, e.g. a firewall alert about a newly-seen IP). Every route here
// shares one token - there's no separate read-only scope, since splitting
// that wasn't asked for and would add a second token type to manage for
// no clear benefit yet.
export const integrationsRouter = Router();
integrationsRouter.use(tokenAuth);

// scannerAgent (agent name) disambiguates when the same ip/hostname now
// exists under more than one scanner agent - see lookupHost below. Optional
// because the common case (one scanner, or an ip that's only ever existed
// on one network) is unambiguous without it - this never breaks an
// existing caller that doesn't know the concept yet.
export const lookupSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
});

// Listing, as opposed to lookup-by-identity above. Every other route
// here needs the caller to already know an ip or hostname, which rules
// out exactly the jobs this API exists for - "give me everything with a
// KEV finding", "what appeared since yesterday", a nightly export. Those
// were only possible from the dashboard, by a human, with a browser.
//
// Reuses parseHostFilterParams/applyHostFilters (exported from
// search/routes.ts, already shared with the saved-search checker) rather
// than growing a second filter dialect, so an external caller's `?port=`
// or `?tag=` means exactly what the same parameter means in the
// dashboard's own URL - and so a filter added there can't silently skip
// this route.
//
// Paginated with a hard cap: the dashboard defaults to 50 and an
// automated caller has more reason to ask for a lot at once, so this
// allows more (200) but never unbounded - an unpaginated fleet dump is
// the one shape that could turn a single call into a real load problem.
export const listHostsSchema = z.object({
  q: z.string().min(1).optional(),
  port: z.string().min(1).optional(),
  service: z.string().min(1).optional(),
  tag: z.string().min(1).optional(),
  osFamily: z.string().min(1).optional(),
  deviceType: z.string().min(1).optional(),
  scannerAgentId: z.string().min(1).optional(),
  hasStalePorts: z.enum(["true", "false"]).optional(),
  lastSeenAfter: z.string().min(1).optional(),
  lastSeenBefore: z.string().min(1).optional(),
  page: z.coerce.number().int().min(1).optional(),
  pageSize: z.coerce.number().int().min(1).max(200).optional(),
});

integrationsRouter.get("/hosts", asyncHandler(async (req, res) => {
  const parsed = listHostsSchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const page = parsed.data.page ?? 1;
  const pageSize = parsed.data.pageSize ?? 50;
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);

  // No scanner restriction: a token isn't a user session and has no
  // per-user scanner scoping (see apiTokens/tokenAuth.ts) - the same
  // unrestricted view every other route in this router already returns.
  const base = () => applyHostFilters(db.selectFrom("hosts").leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id"), filters, null);

  // applyHostFilters is deliberately loosely typed (it serves callers
  // selecting different column sets), so the count and the row shape are
  // spelled out here rather than inferred.
  const countRow: { count: string } = await base()
    .select(sql<string>`count(distinct hosts.id)`.as("count"))
    .executeTakeFirstOrThrow();

  const rows = await base()
    .select([
      "hosts.id",
      "hosts.ip",
      "hosts.hostname",
      "hosts.first_seen_at",
      "hosts.last_seen_at",
      "hosts.os_family",
      "hosts.device_type",
      "hosts.mac_address",
      "scanner_agents.name as scanner_agent_name",
    ])
    .groupBy(["hosts.id", "scanner_agents.name"])
    .orderBy("hosts.last_seen_at", "desc")
    .limit(pageSize)
    .offset((page - 1) * pageSize)
    .execute();

  res.json({
    // hosts.ip is Postgres inet, which node-postgres returns as a string
    // already - normalized explicitly so the JSON shape can't depend on
    // that driver detail.
    items: (rows as Array<Record<string, unknown>>).map((h) => ({ ...h, ip: String(h.ip) })),
    total: Number(countRow.count),
    page,
    pageSize,
  });
}));

integrationsRouter.get("/hosts/lookup", asyncHandler(async (req, res) => {
  const parsed = lookupSchema.safeParse(req.query);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: "provide an ip or hostname query parameter" });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent);
  if (result.status === "not_found") {
    res.status(404).json({ error: "host not found" });
    return;
  }
  if (result.status === "ambiguous") {
    res.status(409).json({
      error: "multiple hosts match - the same ip/hostname exists under more than one scanner agent, pass scannerAgent to disambiguate",
      candidates: result.candidates,
    });
    return;
  }

  res.json(await buildEnrichment(result.host.id));
}));

export const rescanSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
  // "default" / "all_safe" (case-insensitive), or the exact name of a
  // Custom profile - a plain string rather than the dashboard's
  // {kind, profileId} shape, since an external caller has no reason to
  // know a Custom profile's internal uuid, only the name an admin gave
  // it on the Scan Profiles page. Omitted entirely means Default, same
  // as before this existed - this never breaks an existing caller that
  // doesn't know the concept yet.
  profile: z.string().min(1).optional(),
});

// Resolves the External API's flat, name-based `profile` string into the
// {kind, profileId} shape requestRescan actually takes. Looked up (not
// guessed) so an unrecognized name fails clearly with the exact
// candidate profile names, rather than silently falling back to Default
// or reaching requestRescan's own less specific ScanProfileNotFoundError.
async function resolveProfileParam(profile: string | undefined): Promise<{ ok: true; selection: NSEProfileSelection } | { ok: false; error: string }> {
  if (!profile) {
    return { ok: true, selection: { kind: "default" } };
  }
  const normalized = profile.trim().toLowerCase();
  if (normalized === "default") {
    return { ok: true, selection: { kind: "default" } };
  }
  if (normalized === "all_safe" || normalized === "all safe modules") {
    return { ok: true, selection: { kind: "all_safe" } };
  }
  const customProfile = await db.selectFrom("scan_profiles").select(["id"]).where("name", "=", profile).executeTakeFirst();
  if (!customProfile) {
    return { ok: false, error: `unknown scan profile "${profile}" - use "default", "all_safe", or the exact name of an existing Custom profile` };
  }
  return { ok: true, selection: { kind: "custom", profileId: customProfile.id } };
}

// Same flat-string-to-selection idea as resolveProfileParam above, for
// the independent nuclei profile pick - "off" (nuclei never runs, the
// default if omitted) / "safe" / the exact name of a Custom nuclei
// profile.
async function resolveNucleiProfileParam(nucleiProfile: string | undefined): Promise<{ ok: true; selection: NucleiProfileSelection } | { ok: false; error: string }> {
  if (!nucleiProfile) {
    return { ok: true, selection: { kind: "off" } };
  }
  const normalized = nucleiProfile.trim().toLowerCase();
  if (normalized === "off") {
    return { ok: true, selection: { kind: "off" } };
  }
  if (normalized === "safe") {
    return { ok: true, selection: { kind: "safe" } };
  }
  const customProfile = await db.selectFrom("nuclei_profiles").select(["id"]).where("name", "=", nucleiProfile).executeTakeFirst();
  if (!customProfile) {
    return { ok: false, error: `unknown nuclei profile "${nucleiProfile}" - use "off", "safe", or the exact name of an existing Custom nuclei profile` };
  }
  return { ok: true, selection: { kind: "custom", profileId: customProfile.id } };
}

integrationsRouter.post("/hosts/rescan", asyncHandler(async (req, res) => {
  const parsed = rescanSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: "provide an ip or hostname in the request body" });
    return;
  }

  const resolvedProfile = await resolveProfileParam(parsed.data.profile);
  if (!resolvedProfile.ok) {
    res.status(400).json({ error: resolvedProfile.error });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent);
  if (result.status === "not_found") {
    res.status(404).json({ error: "host not found" });
    return;
  }
  if (result.status === "ambiguous") {
    res.status(409).json({
      error: "multiple hosts match - the same ip/hostname exists under more than one scanner agent, pass scannerAgent to disambiguate",
      candidates: result.candidates,
    });
    return;
  }
  const host = result.host;

  const requestedBy = `api-token:${req.apiTokenName}`;
  const outcome = await requestRescan(host.id, requestedBy, resolvedProfile.selection);
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({
    event: "rescan.requested",
    scan_request_id: outcome.request.id,
    host_id: host.id,
    requested_by: requestedBy,
    api_token_id: req.apiTokenId,
    source_ip: req.ip,
  });
  recordAudit("rescan.requested", requestedBy, req.ip, { host_id: host.id, api_token_id: req.apiTokenId });

  res.status(201).json({
    scanRequestId: outcome.request.id,
    status: outcome.request.status,
    createdAt: outcome.request.created_at,
    profile: outcome.request.nse_profile_label,
  });
}));

export const cancelScanSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
});

// Stops whatever scan is currently running against this host - but only
// ever one triggered through the scan_requests queue (rescan button/
// schedules), the same mechanism requestRescan above uses, not an
// arbitrary ad-hoc scan a scanner's own local "serve" REST API happens to
// be running that includes this host's IP in a wider range. host_id ->
// scan_job isn't a direct link while a scan is still in progress (only
// scan_requests.scan_job_id gets set, and only once the scan finishes),
// so this resolves it via the currently "claimed" scan_requests row's
// scanner_agent_id/target_spec/port_spec, which pollOnce used verbatim to
// create the matching scan_jobs row.
integrationsRouter.post("/hosts/cancel-scan", asyncHandler(async (req, res) => {
  const parsed = cancelScanSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: "provide an ip or hostname in the request body" });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent);
  if (result.status === "not_found") {
    res.status(404).json({ error: "host not found" });
    return;
  }
  if (result.status === "ambiguous") {
    res.status(409).json({
      error: "multiple hosts match - the same ip/hostname exists under more than one scanner agent, pass scannerAgent to disambiguate",
      candidates: result.candidates,
    });
    return;
  }
  const host = result.host;

  const claimedRequest = await db
    .selectFrom("scan_requests")
    .select(["scanner_agent_id", "target_spec", "port_spec"])
    .where("host_id", "=", host.id)
    .where("status", "=", "claimed")
    .orderBy("created_at", "desc")
    .executeTakeFirst();
  if (!claimedRequest) {
    res.status(404).json({ error: "no scan currently running for this host" });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("scanner_agent_id", "=", claimedRequest.scanner_agent_id)
    .where("target_spec", "=", claimedRequest.target_spec)
    .where("port_spec", "=", claimedRequest.port_spec)
    .where("status", "=", "running")
    .orderBy("started_at", "desc")
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "no scan currently running for this host" });
    return;
  }

  const requestedBy = `api-token:${req.apiTokenName}`;
  const outcome = await requestScanCancel(job.id);
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({
    event: "scan_job.cancel_requested",
    scan_job_id: job.id,
    host_id: host.id,
    requested_by: requestedBy,
    api_token_id: req.apiTokenId,
    source_ip: req.ip,
  });
  recordAudit("scan_job.cancel_requested", requestedBy, req.ip, {
    scan_job_id: job.id,
    host_id: host.id,
    api_token_id: req.apiTokenId,
  });

  res.status(204).end();
}));

export const adhocScanSchema = z.object({
  scannerAgent: z.string().min(1),
  targetSpec: z.string().trim().min(1),
  portSpec: z.string().trim().min(1),
  profile: z.string().min(1).optional(),
  nucleiProfile: z.string().min(1).optional(),
  // Optional per-scan override of the scanner's own configured
  // masscanRate - omitted/null means the scanner keeps using its config
  // value, so this never changes behavior for anyone who doesn't set it.
  masscanRate: z.number().int().min(1).max(10_000_000).optional(),
});

// Ad-hoc Scans' External API counterpart - the one route in this router
// that doesn't require an existing host, unlike /hosts/rescan and
// /hosts/cancel-scan above. Reuses the identical scan_requests insert
// shape the dashboard's own POST /api/adhoc-scans (adhocScans/routes.ts)
// already uses - same queue, same scanner-side pickup via
// GET /api/ingest/scan-requests/next, just triggered by a token instead
// of a session. scannerAgent is looked up by name (not the dashboard's
// internal uuid), matching every other External API route's convention
// of never expecting a caller to know this app's own internal ids.
integrationsRouter.post("/scans/adhoc", asyncHandler(async (req, res) => {
  const parsed = adhocScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const agent = await db
    .selectFrom("scanner_agents")
    .select(["id", "name"])
    .where("name", "=", parsed.data.scannerAgent)
    .executeTakeFirst();
  if (!agent) {
    res.status(400).json({ error: "unknown scanner agent" });
    return;
  }

  const resolvedProfile = await resolveProfileParam(parsed.data.profile);
  if (!resolvedProfile.ok) {
    res.status(400).json({ error: resolvedProfile.error });
    return;
  }
  const resolvedNucleiProfile = await resolveNucleiProfileParam(parsed.data.nucleiProfile);
  if (!resolvedNucleiProfile.ok) {
    res.status(400).json({ error: resolvedNucleiProfile.error });
    return;
  }

  let nseResolution;
  try {
    nseResolution = await resolveNSEProfile(resolvedProfile.selection);
  } catch (err) {
    if (err instanceof ScanProfileNotFoundError) {
      res.status(400).json({ error: err.message });
      return;
    }
    throw err;
  }

  let nucleiResolution;
  try {
    nucleiResolution = await resolveNucleiProfile(resolvedNucleiProfile.selection);
  } catch (err) {
    if (err instanceof NucleiProfileNotFoundError) {
      res.status(400).json({ error: err.message });
      return;
    }
    throw err;
  }

  const requestedBy = `api-token:${req.apiTokenName}`;
  const request = await db
    .insertInto("scan_requests")
    .values({
      scanner_agent_id: agent.id,
      host_id: null,
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
      requested_by: requestedBy,
      nse_profile: nseResolution.nseProfile,
      nse_scripts: nseResolution.nseScripts,
      nse_profile_label: nseResolution.nseProfileLabel,
      nuclei_profile: nucleiResolution.nucleiProfile,
      nuclei_tags: nucleiResolution.nucleiTags,
      nuclei_profile_label: nucleiResolution.nucleiProfileLabel,
      masscan_rate: parsed.data.masscanRate ?? null,
    })
    .returning(["id", "status", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "adhoc_scan.requested",
    scan_request_id: request.id,
    scanner_agent_id: agent.id,
    scanner_agent_name: agent.name,
    target_spec: parsed.data.targetSpec,
    port_spec: parsed.data.portSpec,
    requested_by: requestedBy,
    api_token_id: req.apiTokenId,
    source_ip: req.ip,
  });
  recordAudit("adhoc_scan.requested", requestedBy, req.ip, {
    scan_request_id: request.id,
    scanner_agent_id: agent.id,
    scanner_agent_name: agent.name,
    target_spec: parsed.data.targetSpec,
    port_spec: parsed.data.portSpec,
    api_token_id: req.apiTokenId,
  });

  res.status(201).json({
    scanRequestId: request.id,
    status: request.status,
    createdAt: request.created_at,
    scannerAgentName: agent.name,
    profile: nseResolution.nseProfileLabel,
    nucleiProfile: nucleiResolution.nucleiProfileLabel,
  });
}));

// Triage from outside the dashboard - the case this exists for is a SOAR
// or ticketing system closing a remediation ticket and wanting the
// finding to stop resurfacing, which otherwise stays a manual step
// someone has to remember. The host is identified the same way every
// other route here does it (ip/hostname + optional scannerAgent, via
// lookupHost), never by internal uuid: an external caller has no way to
// know PortTorch's own ids, and the ambiguity handling comes for free.
export const triageSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
  // Which finding: a CVE id, or a nuclei template id plus the URL it
  // matched (the same identity the dashboard uses - see
  // findingTriage/routes.ts).
  cveId: z.string().min(1).optional(),
  templateId: z.string().min(1).optional(),
  matchedAt: z.string().min(1).optional(),
  state: z.enum(["false_positive", "accepted_risk", "fixed"]),
  note: z.string().trim().max(2000).optional(),
  // ISO timestamp after which the decision lapses and the finding comes
  // back. Omitted = never expires.
  reviewAt: z.string().datetime().nullable().optional(),
});

export const clearTriageSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
  cveId: z.string().min(1).optional(),
  templateId: z.string().min(1).optional(),
  matchedAt: z.string().min(1).optional(),
});

// Both triage routes accept either finding shape in one flat body, so
// this is where "exactly one of them, fully specified" is enforced -
// the dashboard's own route gets this from a discriminated union, which
// doesn't fit an external API that shouldn't require a "kind" field.
function resolveTriageTarget(input: {
  cveId?: string;
  templateId?: string;
  matchedAt?: string;
}): { ok: true; kind: "cve" | "nuclei" } | { ok: false; error: string } {
  const isCve = !!input.cveId;
  const isNuclei = !!input.templateId || !!input.matchedAt;
  if (isCve && isNuclei) {
    return { ok: false, error: "provide either cveId, or templateId+matchedAt - not both" };
  }
  if (isCve) return { ok: true, kind: "cve" };
  if (input.templateId && input.matchedAt) return { ok: true, kind: "nuclei" };
  if (isNuclei) return { ok: false, error: "a nuclei finding needs both templateId and matchedAt" };
  return { ok: false, error: "provide a cveId, or templateId+matchedAt, to identify the finding" };
}

integrationsRouter.put("/findings/triage", asyncHandler(async (req, res) => {
  const parsed = triageSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: parsed.success ? "provide an ip or hostname in the request body" : parsed.error.flatten() });
    return;
  }
  const target = resolveTriageTarget(parsed.data);
  if (!target.ok) {
    res.status(400).json({ error: target.error });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent);
  if (result.status === "not_found") {
    res.status(404).json({ error: "host not found" });
    return;
  }
  if (result.status === "ambiguous") {
    res.status(409).json({
      error: "multiple hosts match - the same ip/hostname exists under more than one scanner agent, pass scannerAgent to disambiguate",
      candidates: result.candidates,
    });
    return;
  }

  const values = {
    kind: target.kind,
    host_id: result.host.id,
    cve_id: target.kind === "cve" ? parsed.data.cveId! : null,
    template_id: target.kind === "nuclei" ? parsed.data.templateId! : null,
    matched_at: target.kind === "nuclei" ? parsed.data.matchedAt! : null,
    state: parsed.data.state,
    note: parsed.data.note ?? null,
    review_at: parsed.data.reviewAt ?? null,
    created_by: `api-token:${req.apiTokenName}`,
  };

  const row = await db
    .insertInto("finding_triage")
    .values(values)
    .onConflict((oc) =>
      oc
        .columns(target.kind === "cve" ? ["host_id", "cve_id"] : ["host_id", "template_id", "matched_at"])
        .where("kind", "=", target.kind)
        .doUpdateSet({
          state: values.state,
          note: values.note,
          review_at: values.review_at,
          created_by: values.created_by,
          updated_at: new Date().toISOString(),
        })
    )
    .returning(["id", "state", "note", "review_at"])
    .executeTakeFirstOrThrow();

  const identity = target.kind === "cve" ? { cve_id: values.cve_id } : { template_id: values.template_id, matched_at: values.matched_at };
  logger.info({
    event: "finding.triaged",
    kind: target.kind,
    host_id: result.host.id,
    ...identity,
    state: values.state,
    review_at: values.review_at,
    triaged_by: values.created_by,
    api_token_id: req.apiTokenId,
    source_ip: req.ip,
  });
  recordAudit("finding.triaged", values.created_by, req.ip, {
    kind: target.kind,
    host_id: result.host.id,
    ...identity,
    state: values.state,
    api_token_id: req.apiTokenId,
  });

  res.json({ id: row.id, state: row.state, note: row.note, reviewAt: row.review_at });
}));

integrationsRouter.delete("/findings/triage", asyncHandler(async (req, res) => {
  const parsed = clearTriageSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: parsed.success ? "provide an ip or hostname in the request body" : parsed.error.flatten() });
    return;
  }
  const target = resolveTriageTarget(parsed.data);
  if (!target.ok) {
    res.status(400).json({ error: target.error });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent);
  if (result.status === "not_found") {
    res.status(404).json({ error: "host not found" });
    return;
  }
  if (result.status === "ambiguous") {
    res.status(409).json({
      error: "multiple hosts match - the same ip/hostname exists under more than one scanner agent, pass scannerAgent to disambiguate",
      candidates: result.candidates,
    });
    return;
  }

  let query = db.deleteFrom("finding_triage").where("kind", "=", target.kind).where("host_id", "=", result.host.id);
  query =
    target.kind === "cve"
      ? query.where("cve_id", "=", parsed.data.cveId!)
      : query.where("template_id", "=", parsed.data.templateId!).where("matched_at", "=", parsed.data.matchedAt!);

  const deleted = await query.executeTakeFirst();
  if (deleted.numDeletedRows === 0n) {
    res.status(404).json({ error: "no triage state set for this finding" });
    return;
  }

  const requestedBy = `api-token:${req.apiTokenName}`;
  logger.info({
    event: "finding.triage_cleared",
    kind: target.kind,
    host_id: result.host.id,
    cleared_by: requestedBy,
    api_token_id: req.apiTokenId,
    source_ip: req.ip,
  });
  recordAudit("finding.triage_cleared", requestedBy, req.ip, {
    kind: target.kind,
    host_id: result.host.id,
    api_token_id: req.apiTokenId,
  });

  res.status(204).end();
}));

type LookupResult =
  | { status: "not_found" }
  | { status: "ambiguous"; candidates: { id: string; ip: string; hostname: string | null; scannerAgentName: string | null }[] }
  | { status: "found"; host: { id: string } };

// A host's identity is (ip, scanner_agent_id), not ip alone - two
// different scanners (different, non-interconnected networks) can each
// have a real device at the same ip. An external caller that doesn't
// specify scannerAgent gets an unambiguous match automatically in the
// common case (one scanner, or an ip that only exists on one network);
// only when that's not enough do we ask them to disambiguate, rather than
// silently guessing which of several real devices they meant.
async function lookupHost(ip: string | undefined, hostname: string | undefined, scannerAgent?: string): Promise<LookupResult> {
  let query = db
    .selectFrom("hosts")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select(["hosts.id as id", "hosts.ip as ip", "hosts.hostname as hostname", "scanner_agents.name as scannerAgentName"]);
  query = ip ? query.where("hosts.ip", "=", ip) : query.where("hosts.hostname", "=", hostname!);
  if (scannerAgent) {
    query = query.where("scanner_agents.name", "=", scannerAgent);
  }

  const matches = await query.execute();
  if (matches.length === 0) {
    return { status: "not_found" };
  }
  if (matches.length > 1) {
    return {
      status: "ambiguous",
      candidates: matches.map((m) => ({ id: m.id, ip: m.ip, hostname: m.hostname, scannerAgentName: m.scannerAgentName })),
    };
  }
  return { status: "found", host: { id: matches[0].id } };
}

// Deliberately flatter and more self-contained than the dashboard's
// GET /api/hosts/:id response (no internal ids beyond the host's own,
// camelCase throughout) - this is consumed by external tooling, not the
// React frontend, so it isn't tied to that endpoint's shape.
async function buildEnrichment(hostId: string) {
  const host = await db
    .selectFrom("hosts")
    .select([
      "id",
      "ip",
      "hostname",
      "os_name",
      "os_family",
      "os_vendor",
      "device_type",
      "os_accuracy",
      "first_seen_at",
      "last_seen_at",
    ])
    .where("id", "=", hostId)
    .executeTakeFirstOrThrow();

  const rawPorts = await db
    .selectFrom("current_host_ports")
    .selectAll()
    .where("host_id", "=", hostId)
    .where("state", "=", "open")
    .orderBy("port")
    .execute();

  const allCpes = [...new Set(rawPorts.flatMap((p) => p.cpes ?? []))];
  const cveRows = allCpes.length > 0 ? await db.selectFrom("cve_cache").select(["cpe", "cves"]).where("cpe", "in", allCpes).execute() : [];
  const cvesByCpe = new Map(cveRows.map((r) => [r.cpe, r.cves]));

  const ports = rawPorts.map((p) => {
    const vulnerabilities = new Map<string, (typeof cveRows)[number]["cves"][number]>();
    for (const cpe of p.cpes ?? []) {
      for (const cve of cvesByCpe.get(cpe) ?? []) {
        vulnerabilities.set(cve.id, cve);
      }
    }
    return {
      port: p.port,
      protocol: p.protocol,
      service: p.service_name,
      product: p.service_product,
      version: p.service_version,
      banner: p.banner,
      cpes: p.cpes ?? [],
      vulnerabilities: [...vulnerabilities.values()],
      observedAt: p.observed_at,
    };
  });

  const tags = await db.selectFrom("host_tags").select(["tag"]).where("host_id", "=", hostId).orderBy("tag").execute();

  const lastScan = await db
    .selectFrom("host_port_observations")
    .innerJoin("scan_jobs", "scan_jobs.id", "host_port_observations.scan_job_id")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .select(["host_port_observations.observed_at as observed_at", "scanner_agents.name as scanner_agent_name"])
    .where("host_port_observations.host_id", "=", hostId)
    .orderBy("host_port_observations.observed_at", "desc")
    .executeTakeFirst();

  const lastScanRequest = await db
    .selectFrom("scan_requests")
    .select(["status", "created_at", "completed_at"])
    .where("host_id", "=", hostId)
    .orderBy("created_at", "desc")
    .executeTakeFirst();

  return {
    ip: host.ip,
    hostname: host.hostname,
    os: {
      name: host.os_name,
      family: host.os_family,
      vendor: host.os_vendor,
      deviceType: host.device_type,
      accuracy: host.os_accuracy,
    },
    firstSeenAt: host.first_seen_at,
    lastSeenAt: host.last_seen_at,
    tags: tags.map((t) => t.tag),
    openPorts: ports,
    lastScan: lastScan ? { observedAt: lastScan.observed_at, scannerAgentName: lastScan.scanner_agent_name } : null,
    lastScanRequest: lastScanRequest ?? null,
  };
}
