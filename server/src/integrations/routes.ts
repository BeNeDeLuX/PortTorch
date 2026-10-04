import { Router } from "express";
import { z } from "zod";
import { targetSpecSchema } from "../lib/targetSpec";
import { normalizeScanTags, scanTagsSchema } from "../lib/scanTags";
import { sql } from "kysely";
import { db } from "../db";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestRescan } from "../rescan";
import { DEFAULT_SCAN_PRIORITY, scanPrioritySchema } from "../scanPriority";
import { requestScanCancel } from "../scanCancel";
import { getTokenScannerAgentIds, requireTokenWrite, tokenAuth } from "../apiTokens/tokenAuth";
import { queueScan } from "../scanGroups/queue";
import { MAX_SPLIT_SCANNERS } from "../lib/scanSplit";
import { zIp } from "../lib/zodIp";
import { approveBaseline, baselineWithChanges, listBaselineSummaries } from "../baselines/service";
import { listPolicySummaries, policyWithViolations } from "../portPolicies/service";
import { computeNetworkChanges, DAY_MS, parseNetwork } from "../subnets/changes";
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
// entirely, e.g. a firewall alert about a newly-seen IP).
//
// A token carries a scope and, optionally, a scanner restriction (see the
// api_token_scopes migration). Everything that *changes* something here -
// rescan, cancel-scan, ad-hoc scan, deleting a triage decision - is
// behind requireTokenWrite, so a token handed to a reporting script or a
// dashboard panel cannot launch scans across the network. The read routes
// apply the token's scanner restriction the same way a session's is
// applied elsewhere.
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

  // The token's own scanner restriction, in exactly the shape a session's
  // is (null = unrestricted), so applyHostFilters needs no knowledge of
  // which auth chain the caller came through.
  const allowed = getTokenScannerAgentIds(req);
  const base = () =>
    applyHostFilters(
      db.selectFrom("hosts").leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id"),
      filters,
      allowed
    );

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

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent, getTokenScannerAgentIds(req));
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
  // "high" | "normal" | "low" - same claim-order control the ad-hoc
  // endpoint below takes; omitted keeps the pre-priority 'normal'.
  priority: scanPrioritySchema.optional(),
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

integrationsRouter.post("/hosts/rescan", requireTokenWrite, asyncHandler(async (req, res) => {
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

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent, getTokenScannerAgentIds(req));
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
  const outcome = await requestRescan(
    host.id,
    requestedBy,
    resolvedProfile.selection,
    { kind: "off" },
    parsed.data.priority ?? DEFAULT_SCAN_PRIORITY
  );
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
// be running that includes this host's IP in a wider range. Resolved via
// the currently "claimed" scan_requests row: its scan_job_id when the
// scanner named the request on starting the job, otherwise its
// scanner_agent_id/target_spec/port_spec, which pollOnce used verbatim to
// create the matching scan_jobs row.
integrationsRouter.post("/hosts/cancel-scan", requireTokenWrite, asyncHandler(async (req, res) => {
  const parsed = cancelScanSchema.safeParse(req.body);
  if (!parsed.success || (!parsed.data.ip && !parsed.data.hostname)) {
    res.status(400).json({ error: "provide an ip or hostname in the request body" });
    return;
  }

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent, getTokenScannerAgentIds(req));
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
    .select(["scanner_agent_id", "target_spec", "port_spec", "scan_job_id"])
    .where("host_id", "=", host.id)
    .where("status", "=", "claimed")
    .orderBy("created_at", "desc")
    .executeTakeFirst();
  if (!claimedRequest) {
    res.status(404).json({ error: "no scan currently running for this host" });
    return;
  }

  // A scanner from 0.28.0 names the request when it starts the job, so
  // the link is exact. An older one does not, and the job is found the
  // way it always was: the running job created from this request's own
  // scanner, target and ports.
  const job = claimedRequest.scan_job_id
    ? { id: claimedRequest.scan_job_id }
    : await db
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

export const adhocScanSchema = z
  .object({
    // One scanner by name, as always - or several, to split the target
    // between them (see lib/scanSplit.ts). Names rather than ids, the
    // convention every route here follows.
    scannerAgent: z.string().min(1).optional(),
    scannerAgents: z.array(z.string().min(1)).min(1).max(MAX_SPLIT_SCANNERS).optional(),
    // With several scanners, masscanRate is the total for the whole scan,
    // divided between them - so the target network sees the load of one
    // scanner rather than one per scanner.
    masscanRateSplit: z.boolean().optional(),
    targetSpec: targetSpecSchema,
    portSpec: z.string().trim().min(1),
    profile: z.string().min(1).optional(),
    nucleiProfile: z.string().min(1).optional(),
    // Optional per-scan override of the scanner's own configured
    // masscanRate - omitted/null means the scanner keeps using its config
    // value, so this never changes behavior for anyone who doesn't set it.
    masscanRate: z.number().int().min(1).max(10_000_000).optional(),
    // "high" | "normal" | "low" - where this lands in the target scanner's
    // claim order. Omitted keeps the pre-priority behavior ('normal').
    priority: scanPrioritySchema.optional(),
    // Applied to every host this scan actually touches - see lib/scanTags.ts
    // and the dashboard's own Ad-hoc Scans page, which this mirrors.
    tags: scanTagsSchema,
  })
  .refine((d) => d.scannerAgent !== undefined || d.scannerAgents !== undefined, {
    message: "give scannerAgent or scannerAgents",
  })
  .refine((d) => !d.masscanRateSplit || d.masscanRate !== undefined, {
    message: "masscanRateSplit needs a masscanRate to divide",
  });

// Ad-hoc Scans' External API counterpart - the one route in this router
// that doesn't require an existing host, unlike /hosts/rescan and
// /hosts/cancel-scan above. Queues through the same queueScan the
// dashboard's own POST /api/adhoc-scans uses - same queue, same split,
// same scanner-side pickup via GET /api/ingest/scan-requests/next, just
// triggered by a token instead of a session. Scanners are looked up by
// name (not the dashboard's internal uuid), matching every other External
// API route's convention of never expecting a caller to know this app's
// own internal ids.
//
// A token restricted to certain scanners may only queue on those - the
// restriction every other route here already honours through lookupHost.
// This route queued on any scanner by name until that was noticed while
// adding the multi-scanner form; pinned by a test now.
integrationsRouter.post("/scans/adhoc", requireTokenWrite, asyncHandler(async (req, res) => {
  const parsed = adhocScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const names = [...new Set(parsed.data.scannerAgents ?? [parsed.data.scannerAgent!])];
  const agents = await db.selectFrom("scanner_agents").select(["id", "name", "revoked_at"]).where("name", "in", names).execute();
  const byName = new Map(agents.map((a) => [a.name, a]));
  const unknown = names.filter((n) => !byName.has(n));
  if (unknown.length > 0) {
    res.status(400).json({ error: `unknown scanner agent: ${unknown.join(", ")}` });
    return;
  }
  const chosen = names.map((n) => byName.get(n)!);
  const allowed = getTokenScannerAgentIds(req);
  if (allowed && chosen.some((a) => !allowed.includes(a.id))) {
    res.status(403).json({ error: "this token is not allowed to use that scanner agent" });
    return;
  }
  // A revoked scanner would never claim its share of a split.
  if (chosen.length > 1 && chosen.some((a) => a.revoked_at)) {
    res.status(400).json({ error: "a revoked scanner cannot take part in a split scan" });
    return;
  }
  const nameOf = new Map(chosen.map((a) => [a.id, a.name]));

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
  const tags = normalizeScanTags(parsed.data.tags);
  const queued = await db.transaction().execute((trx) =>
    queueScan(
      trx,
      parsed.data.targetSpec,
      chosen.map((a) => a.id),
      {
        port_spec: parsed.data.portSpec,
        requested_by: requestedBy,
        nse_profile: nseResolution.nseProfile,
        nse_scripts: nseResolution.nseScripts,
        nse_profile_label: nseResolution.nseProfileLabel,
        nuclei_profile: nucleiResolution.nucleiProfile,
        nuclei_tags: nucleiResolution.nucleiTags,
        nuclei_profile_label: nucleiResolution.nucleiProfileLabel,
        masscan_rate: parsed.data.masscanRate ?? null,
        priority: parsed.data.priority ?? DEFAULT_SCAN_PRIORITY,
        tags,
        schedule_id: null,
      },
      parsed.data.masscanRateSplit ?? false
    )
  );
  if (!queued.ok) {
    res.status(400).json({ error: queued.error });
    return;
  }

  for (const part of queued.parts) {
    logger.info({
      event: "adhoc_scan.requested",
      scan_request_id: part.id,
      scan_group_id: queued.groupId,
      scanner_agent_id: part.scannerAgentId,
      scanner_agent_name: nameOf.get(part.scannerAgentId),
      target_spec: part.targetSpec,
      port_spec: parsed.data.portSpec,
      masscan_rate: part.masscanRate,
      tags,
      requested_by: requestedBy,
      api_token_id: req.apiTokenId,
      source_ip: req.ip,
    });
  }
  recordAudit("adhoc_scan.requested", requestedBy, req.ip, {
    scan_request_id: queued.parts[0].id,
    scan_group_id: queued.groupId,
    scanner_agent_ids: queued.parts.map((p) => p.scannerAgentId),
    target_spec: parsed.data.targetSpec,
    port_spec: parsed.data.portSpec,
    tags,
    api_token_id: req.apiTokenId,
  });

  // The first part at the top level keeps the response every caller
  // written before splitting existed reads; `parts` is the whole picture.
  const first = queued.parts[0];
  res.status(201).json({
    scanRequestId: first.id,
    status: "pending",
    createdAt: new Date().toISOString(),
    scannerAgentName: nameOf.get(first.scannerAgentId),
    profile: nseResolution.nseProfileLabel,
    nucleiProfile: nucleiResolution.nucleiProfileLabel,
    tags,
    scanGroupId: queued.groupId,
    parts: queued.parts.map((p) => ({
      scanRequestId: p.id,
      scannerAgentName: nameOf.get(p.scannerAgentId),
      targetSpec: p.targetSpec,
      addresses: p.addresses,
      masscanRate: p.masscanRate,
    })),
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

// requireTokenWrite was missing here until a real gap was found: DELETE
// right below has always had it, but this route - which mutates the same
// row (sets false_positive/accepted_risk/fixed, silencing a finding
// fleet-wide for that host) - did not, so a read-only token could
// triage findings despite the scope existing precisely to stop that.
integrationsRouter.put("/findings/triage", requireTokenWrite, asyncHandler(async (req, res) => {
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

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent, getTokenScannerAgentIds(req));
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

integrationsRouter.delete("/findings/triage", requireTokenWrite, asyncHandler(async (req, res) => {
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

  const result = await lookupHost(parsed.data.ip, parsed.data.hostname, parsed.data.scannerAgent, getTokenScannerAgentIds(req));
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
// allowedScannerAgentIds is the calling token's own restriction (null =
// unrestricted). Applied here rather than at each call site because every
// endpoint that resolves an ip/hostname to a host goes through this - a
// restriction that only covered the list endpoint would be no restriction
// at all, since /hosts/lookup returns the same host by another route.
async function lookupHost(
  ip: string | undefined,
  hostname: string | undefined,
  scannerAgent: string | undefined,
  allowedScannerAgentIds: string[] | null
): Promise<LookupResult> {
  let query = db
    .selectFrom("hosts")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select(["hosts.id as id", "hosts.ip as ip", "hosts.hostname as hostname", "scanner_agents.name as scannerAgentName"]);
  query = ip ? query.where("hosts.ip", "=", ip) : query.where("hosts.hostname", "=", hostname!);
  if (scannerAgent) {
    query = query.where("scanner_agents.name", "=", scannerAgent);
  }
  if (allowedScannerAgentIds) {
    query = query.where("hosts.scanner_agent_id", "in", allowedScannerAgentIds);
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
      "mac_address",
      "mac_vendor",
      "derived_hostname",
      "derived_hostname_source",
      "derived_mac_address",
      "derived_mac_vendor",
      "derived_mac_source",
      "windows_build",
      "windows_build_source",
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
    // Never merged into `hostname`/`mac`: a caller keying on a name has
    // to be able to tell a PTR record from a machine's own claim.
    derived: {
      hostname: host.derived_hostname,
      hostnameSource: host.derived_hostname_source,
      macAddress: host.derived_mac_address,
      macVendor: host.derived_mac_vendor,
      macSource: host.derived_mac_source,
      // The exact Windows build from an NTLM message, e.g. "10.0.17763".
      windowsBuild: host.windows_build,
      windowsBuildSource: host.windows_build_source,
    },
    mac: { address: host.mac_address, vendor: host.mac_vendor },
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

// --- Network changes, baselines and port policies --------------------------
//
// The read side of what the dashboard's Changes view, Baselines page and
// Port Policies page show, through the same service functions, so a SOAR
// or ticketing integration sees exactly what an analyst would - scoped by
// the token's scanner restriction the way a session is scoped by its own.
// The one write is approving a baseline: closing a change ticket is the
// moment a deviation becomes expected, and the natural place to say so.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const networkChangesSchema = z.object({
  network: z.string().trim().min(1).max(100).describe("CIDR, address, or a partial IPv4 address such as 10.46"),
  from: z.string().datetime({ offset: true }).optional().describe("Start of the comparison; default 7 days before `to`"),
  to: z.string().datetime({ offset: true }).optional().describe("End of the comparison; default now"),
  scannerAgent: z.string().min(1).optional().describe("Narrow to one scanner agent, by name"),
});

integrationsRouter.get("/networks/changes", asyncHandler(async (req, res) => {
  const parsed = networkChangesSchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const network = parseNetwork(parsed.data.network);
  if (!network) {
    res.status(400).json({ error: "network must be a CIDR, an address, or a partial IPv4 address such as 10.46" });
    return;
  }
  const to = parsed.data.to ? new Date(parsed.data.to) : new Date();
  const from = parsed.data.from ? new Date(parsed.data.from) : new Date(to.getTime() - 7 * DAY_MS);
  if (from >= to) {
    res.status(400).json({ error: "from must be before to" });
    return;
  }
  let filterIds: string[] = [];
  if (parsed.data.scannerAgent) {
    const agent = await db.selectFrom("scanner_agents").select("id").where("name", "=", parsed.data.scannerAgent).executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: `unknown scanner agent "${parsed.data.scannerAgent}"` });
      return;
    }
    filterIds = [agent.id];
  }
  res.json(await computeNetworkChanges({ network, from, to, allowed: getTokenScannerAgentIds(req), filterIds, hideRetired: false }));
}));

integrationsRouter.get("/baselines", asyncHandler(async (req, res) => {
  res.json(await listBaselineSummaries(getTokenScannerAgentIds(req)));
}));

integrationsRouter.get("/baselines/:id", asyncHandler(async (req, res) => {
  const found = UUID_RE.test(String(req.params.id))
    ? await baselineWithChanges(String(req.params.id), getTokenScannerAgentIds(req))
    : null;
  if (!found) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  res.json(found);
}));

export const approveBaselineApiSchema = z.object({
  note: z.string().trim().max(500).nullable().optional().describe("Replaces the baseline's note when given, e.g. the change ticket"),
});

integrationsRouter.post("/baselines/:id/approve", requireTokenWrite, asyncHandler(async (req, res) => {
  const parsed = approveBaselineApiSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const actor = `api-token:${req.apiTokenName}`;
  const visible = UUID_RE.test(String(req.params.id))
    ? await approveBaseline(String(req.params.id), getTokenScannerAgentIds(req), actor, parsed.data.note)
    : null;
  if (!visible) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  logger.info({ event: "baseline.approved", baseline_id: visible.id, network: visible.network, approved_by: actor, source_ip: req.ip });
  recordAudit("baseline.approved", actor, req.ip, { baseline_id: visible.id, network: visible.network, api_token_id: req.apiTokenId });
  res.status(204).end();
}));

integrationsRouter.get("/port-policies", asyncHandler(async (req, res) => {
  res.json(await listPolicySummaries(getTokenScannerAgentIds(req)));
}));

integrationsRouter.get("/port-policies/:id", asyncHandler(async (req, res) => {
  const found = UUID_RE.test(String(req.params.id))
    ? await policyWithViolations(String(req.params.id), getTokenScannerAgentIds(req))
    : null;
  if (!found) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  res.json(found);
}));
