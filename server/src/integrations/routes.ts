import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestRescan } from "../rescan";
import { requestScanCancel } from "../scanCancel";
import { tokenAuth } from "../apiTokens/tokenAuth";
import { zIp } from "../lib/zodIp";
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
const lookupSchema = z.object({
  ip: zIp().optional(),
  hostname: z.string().min(1).optional(),
  scannerAgent: z.string().min(1).optional(),
});

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

const rescanSchema = z.object({
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

const cancelScanSchema = z.object({
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

const adhocScanSchema = z.object({
  scannerAgent: z.string().min(1),
  targetSpec: z.string().trim().min(1),
  portSpec: z.string().trim().min(1),
  profile: z.string().min(1).optional(),
  nucleiProfile: z.string().min(1).optional(),
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
