import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { isStaleScanJob } from "../lib/staleness";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestScanCancel } from "../scanCancel";
import { singleParam } from "../lib/reqParams";
import { getAppSettings } from "../settings/appSettings";

export const scanJobsRouter = Router();
scanJobsRouter.use(requireAuth);

const HISTORY_STATUSES = ["completed", "failed", "cancelled"] as const;
const HISTORY_PAGE_SIZE = 50;
const MAX_HISTORY_PAGE_SIZE = 200;

// Written out per key rather than sorting by the SELECT list's own output
// aliases (which Postgres would technically allow) so this stays an
// explicit, reviewable whitelist - sortKey ultimately comes from the
// query string, and interpolating it anywhere near raw SQL without one
// would be an injection risk.
const HISTORY_SORT_EXPRESSIONS = {
  target_spec: sql`scan_jobs.target_spec`,
  port_spec: sql`scan_jobs.port_spec`,
  scanner_agent_name: sql`scanner_agents.name`,
  status: sql`scan_jobs.status`,
  started_at: sql`scan_jobs.started_at`,
  duration_ms: sql`(scan_jobs.finished_at - scan_jobs.started_at)`,
  hosts_scanned: sql`(select count(distinct host_id) from host_port_observations where scan_job_id = scan_jobs.id)`,
  open_ports_found: sql`(select count(*) from host_port_observations where scan_job_id = scan_jobs.id and state = 'open')`,
  screenshots: sql`((select count(*) from screenshots where scan_job_id = scan_jobs.id) + (select count(*) from rdp_screenshots where scan_job_id = scan_jobs.id))`,
  tls_certificates: sql`(select count(*) from tls_certificates where scan_job_id = scan_jobs.id)`,
} as const;
type HistorySortKey = keyof typeof HISTORY_SORT_EXPRESSIONS;

// Every terminal (non-"running") scan job, most recently finished first -
// the historical counterpart to /active above. hosts_scanned/
// open_ports_found/screenshots/rdp_screenshots/tls_certificates are scalar
// subqueries rather than joins, deliberately: joining host_port_observations
// and screenshots etc. into one query would fan out (a host with 10 ports
// and 2 screenshots would multiply into 20 rows before aggregation),
// double-counting everything. Same counts, and the same reasoning for
// computing them from the DB rather than trusting the scanner's own
// report, as the scan.completed log line in ingest/routes.ts.
scanJobsRouter.get("/history", asyncHandler(async (req, res) => {
  const page = Math.max(1, parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(
    MAX_HISTORY_PAGE_SIZE,
    Math.max(1, parseInt(String(req.query.pageSize ?? HISTORY_PAGE_SIZE), 10) || HISTORY_PAGE_SIZE)
  );
  const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
  const statusParam = typeof req.query.status === "string" ? req.query.status.split(",").filter(Boolean) : [];
  const statuses = statusParam.filter((s): s is (typeof HISTORY_STATUSES)[number] =>
    (HISTORY_STATUSES as readonly string[]).includes(s)
  );
  const sortKeyParam = typeof req.query.sortKey === "string" ? req.query.sortKey : "started_at";
  const sortKey: HistorySortKey = sortKeyParam in HISTORY_SORT_EXPRESSIONS ? (sortKeyParam as HistorySortKey) : "started_at";
  const sortDir = req.query.sortDir === "asc" ? sql`asc` : sql`desc`;
  const allowed = getAllowedScannerAgentIds(req);

  let query = db
    .selectFrom("scan_jobs")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .where("scan_jobs.status", "!=", "running");

  let countQuery = db
    .selectFrom("scan_jobs")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .where("scan_jobs.status", "!=", "running");

  if (allowed) {
    query = query.where("scan_jobs.scanner_agent_id", "in", allowed);
    countQuery = countQuery.where("scan_jobs.scanner_agent_id", "in", allowed);
  }

  if (statuses.length > 0) {
    query = query.where("scan_jobs.status", "in", statuses);
    countQuery = countQuery.where("scan_jobs.status", "in", statuses);
  }
  if (q) {
    const like = `%${q}%`;
    query = query.where((eb) =>
      eb.or([
        eb("scan_jobs.target_spec", "ilike", like),
        eb("scan_jobs.port_spec", "ilike", like),
        eb("scanner_agents.name", "ilike", like),
      ])
    );
    countQuery = countQuery.where((eb) =>
      eb.or([
        eb("scan_jobs.target_spec", "ilike", like),
        eb("scan_jobs.port_spec", "ilike", like),
        eb("scanner_agents.name", "ilike", like),
      ])
    );
  }

  const { count } = await countQuery
    .select(sql<number>`count(*)`.as("count"))
    .executeTakeFirstOrThrow();

  const items = await query
    .select([
      "scan_jobs.id as id",
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scan_jobs.status as status",
      "scan_jobs.started_at as started_at",
      "scan_jobs.finished_at as finished_at",
      "scanner_agents.name as scanner_agent_name",
      sql<number>`(select count(distinct host_id) from host_port_observations where scan_job_id = scan_jobs.id)`.as(
        "hosts_scanned"
      ),
      sql<number>`(select count(*) from host_port_observations where scan_job_id = scan_jobs.id and state = 'open')`.as(
        "open_ports_found"
      ),
      sql<number>`(select count(*) from screenshots where scan_job_id = scan_jobs.id)`.as("screenshots"),
      sql<number>`(select count(*) from rdp_screenshots where scan_job_id = scan_jobs.id)`.as("rdp_screenshots"),
      sql<number>`(select count(*) from tls_certificates where scan_job_id = scan_jobs.id)`.as("tls_certificates"),
    ])
    .orderBy(sql`${HISTORY_SORT_EXPRESSIONS[sortKey]} ${sortDir}`)
    .limit(pageSize)
    .offset((page - 1) * pageSize)
    .execute();

  res.json({
    items: items.map((i) => ({
      ...i,
      // Postgres count(*)/count(distinct ...) are bigint, which node-pg
      // returns as strings (not numbers) to avoid silent precision loss
      // above Number.MAX_SAFE_INTEGER - fine to display directly, but
      // arithmetic on them (the frontend adds screenshots + rdp_screenshots)
      // would silently string-concatenate instead of add without this.
      hosts_scanned: Number(i.hosts_scanned),
      open_ports_found: Number(i.open_ports_found),
      screenshots: Number(i.screenshots),
      rdp_screenshots: Number(i.rdp_screenshots),
      tls_certificates: Number(i.tls_certificates),
      duration_ms: i.finished_at ? i.finished_at.getTime() - i.started_at.getTime() : null,
    })),
    total: Number(count),
    page,
    pageSize,
  });
}));

// "Running" covers every entry point (ad-hoc "scan", "menu", and
// serve-mode requests picked up from the scan_requests queue) since all
// of them call CreateScanJob at the start regardless of how the scan was
// triggered - scan_requests.status = 'claimed' would only cover the
// queue-triggered subset.
scanJobsRouter.get("/active", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let jobsQuery = db
    .selectFrom("scan_jobs")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    // Left, not inner: a job with no progress row yet (the scanner's
    // first push hasn't landed) must still show up here - isStaleScanJob
    // below falls back to started_at in exactly that case.
    .leftJoin("scan_job_progress", "scan_job_progress.scan_job_id", "scan_jobs.id")
    .select([
      "scan_jobs.id as id",
      "scan_jobs.scanner_agent_id as scanner_agent_id",
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scan_jobs.started_at as started_at",
      "scan_jobs.cancellable as cancellable",
      "scan_jobs.cancel_requested_at as cancel_requested_at",
      "scanner_agents.name as scanner_agent_name",
      "scan_job_progress.updated_at as last_progress_at",
    ])
    .where("scan_jobs.status", "=", "running");
  if (allowed) {
    jobsQuery = jobsQuery.where("scan_jobs.scanner_agent_id", "in", allowed);
  }
  const jobs = await jobsQuery.orderBy("scan_jobs.started_at", "asc").execute();
  const { staleScanThresholdMinutes } = await getAppSettings();

  // The target/port spec shown here is what was *requested* - excludes
  // (scan_excludes) are applied scanner-side before masscan ever runs
  // (see CLAUDE.md), so the actual scanned range is narrower whenever an
  // exclude applies. Surfaced here too so "why does this scan only show
  // 30 of the 32 hosts I expected" doesn't require a trip to the Excludes
  // page. scan_excludes management is admin-only, so only admins get this
  // annotation - operators/users still get the base active-scans data.
  const isAdmin = req.session.role === "admin";
  const excludes = isAdmin
    ? await db.selectFrom("scan_excludes").select(["kind", "value", "scanner_agent_id"]).execute()
    : [];

  res.json(
    jobs.map(({ cancel_requested_at, last_progress_at, ...j }) => ({
      ...j,
      is_stale: isStaleScanJob(j.started_at, last_progress_at, staleScanThresholdMinutes),
      cancel_requested: cancel_requested_at !== null,
      ...(isAdmin
        ? {
            applicable_excludes: excludes
              .filter((e) => e.scanner_agent_id === null || e.scanner_agent_id === j.scanner_agent_id)
              .map((e) => ({ kind: e.kind, value: e.value })),
          }
        : {}),
    }))
  );
}));

// Live-ish progress for one running (or just-finished) scan job - the
// "Details" popup on the dashboard's Active Scans banner / Scanner
// Agents' active-scan column polls this while open, and Scan History's
// own "Details" button opens the same popup for an already-finished job
// (ScanProgressModal's `live={false}` mode). Backed by scan_job_progress,
// pushed by the scanner itself every few seconds while it runs (see
// ingest/routes.ts's PATCH .../progress) - this route only ever reads
// whatever the scanner last sent, it never talks to the scanner directly
// (all communication is scanner-initiated). Same read-only access level
// as /active (any authenticated role, not operator-gated) since this is
// just a more detailed view of the same already-visible data, not a new
// capability.
scanJobsRouter.get("/:id/progress", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id", "scanner_agent_id"])
    .where("id", "=", req.params.id)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }
  const allowed = getAllowedScannerAgentIds(req);
  if (allowed && (!job.scanner_agent_id || !allowed.includes(job.scanner_agent_id))) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  const [progress, fullLog] = await Promise.all([
    db
      .selectFrom("scan_job_progress")
      .select(["current_stage", "stage_detail", "recent_logs", "updated_at"])
      .where("scan_job_id", "=", req.params.id)
      .executeTakeFirst(),
    // Uploaded once by the scanner at completion (see ingest/routes.ts's
    // PATCH .../full-log) - preferred over the capped recent_logs above
    // whenever it exists. Absent for a still-running scan (only written
    // at Close()) and for anything that finished before this feature
    // existed or whose upload failed - both fall back to recent_logs
    // below, same "best-effort, graceful degradation" as everywhere else
    // scanner-pushed data is read here.
    db
      .selectFrom("scan_job_full_log")
      .select(["logs"])
      .where("scan_job_id", "=", req.params.id)
      .executeTakeFirst(),
  ]);

  // No row yet just means the scanner hasn't pushed its first update -
  // a real, common state (e.g. right after a scan starts), not an error.
  res.json({
    currentStage: progress?.current_stage ?? null,
    stageDetail: progress?.stage_detail ?? null,
    logs: fullLog?.logs ?? progress?.recent_logs ?? [],
    logsComplete: fullLog !== undefined,
    updatedAt: progress?.updated_at ?? null,
  });
}));

// scan_requests waiting for their scanner to pick them up - a "serve"
// scanner's polling loop blocks for the whole duration of whatever it's
// currently running (see StartPolling/pollOnce), so a rescan or scheduled
// run created while that scanner is already busy just sits here as
// status='pending' until the current job finishes and the loop gets back
// to polling. This is the queued/waiting counterpart to /active (running)
// and /history (finished) above - a scanner_agent_id can appear here even
// while it also has a row in /active, which is exactly the "one more
// request queued up behind the running one" case this exists to surface.
scanJobsRouter.get("/queue", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let queuedQuery = db
    .selectFrom("scan_requests")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_requests.scanner_agent_id")
    .leftJoin("hosts", "hosts.id", "scan_requests.host_id")
    .select([
      "scan_requests.id as id",
      "scan_requests.scanner_agent_id as scanner_agent_id",
      "scan_requests.target_spec as target_spec",
      "scan_requests.port_spec as port_spec",
      "scan_requests.requested_by as requested_by",
      "scan_requests.created_at as created_at",
      "scanner_agents.name as scanner_agent_name",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
    ])
    .where("scan_requests.status", "=", "pending");
  if (allowed) {
    queuedQuery = queuedQuery.where("scan_requests.scanner_agent_id", "in", allowed);
  }
  const queued = await queuedQuery.orderBy("scan_requests.created_at", "asc").execute();

  res.json(queued);
}));

// Cancels a scan_request that's still pending - i.e. no scanner has
// claimed it yet, so unlike /:id/cancel above there's no running process
// anywhere to notify; this is purely a webserver-side state change.
// Marking it 'cancelled' (rather than deleting the row outright) keeps it
// out of every scanner's "next pending request" query - which already
// filters status = 'pending' (see scan-requests/next in ingest/routes.ts)
// - while still leaving a trail behind, consistent with how dismiss above
// handles a stuck scan_job. A schedule that's still enabled will simply
// queue a fresh request on its next tick, same as if this one had run;
// cancelling here doesn't touch scan_schedules.
scanJobsRouter.post("/queue/:id/cancel", requireOperator, asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan request id" });
    return;
  }

  const request = await db
    .selectFrom("scan_requests")
    .select(["id", "status", "scanner_agent_id"])
    .where("id", "=", req.params.id)
    .executeTakeFirst();
  if (!request) {
    res.status(404).json({ error: "scan request not found" });
    return;
  }
  const allowed = getAllowedScannerAgentIds(req);
  if (allowed && (!request.scanner_agent_id || !allowed.includes(request.scanner_agent_id))) {
    res.status(404).json({ error: "scan request not found" });
    return;
  }
  if (request.status !== "pending") {
    res.status(409).json({ error: "scan request is no longer pending" });
    return;
  }

  await db
    .updateTable("scan_requests")
    .set({ status: "cancelled", completed_at: new Date().toISOString() })
    .where("id", "=", req.params.id)
    .execute();

  logger.info({ event: "scan_request.cancelled", scan_request_id: req.params.id, cancelled_by: req.session.username });
  recordAudit("scan_request.cancelled", req.session.username, req.ip, { scan_request_id: req.params.id });

  res.status(204).end();
}));

// Marks a stuck "running" job as "failed" so it drops out of the
// active-scans views - the scanner itself never gets told (there's no
// inbound channel to it). If that scanner is actually still alive and
// later calls PATCH /api/ingest/scan-jobs/:id with its real outcome, that
// update has no status precondition (matches on id + scanner_agent_id
// only) and simply overwrites this "failed" guess - which is the
// behavior we want, since the scanner's own report of what actually
// happened should always win over an admin's guess that it was stuck.
// Same operator-level access as the rescan button - this is routine
// pipeline upkeep, not admin-only config. Deliberately restricted to
// jobs that are actually stale (re-checked server-side, not just trusted
// from what the client last polled) so this can't be used to kill a scan
// that's merely running a long scan.
scanJobsRouter.post("/:id/dismiss", requireOperator, asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id", "started_at", "status", "scanner_agent_id"])
    .where("id", "=", req.params.id)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }
  const allowed = getAllowedScannerAgentIds(req);
  if (allowed && (!job.scanner_agent_id || !allowed.includes(job.scanner_agent_id))) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  const progress = await db
    .selectFrom("scan_job_progress")
    .select(["updated_at"])
    .where("scan_job_id", "=", req.params.id)
    .executeTakeFirst();
  const { staleScanThresholdMinutes } = await getAppSettings();
  if (job.status !== "running" || !isStaleScanJob(job.started_at, progress?.updated_at ?? null, staleScanThresholdMinutes)) {
    res.status(409).json({ error: "scan job is not a stale running job" });
    return;
  }

  await db
    .updateTable("scan_jobs")
    .set({ status: "failed", finished_at: new Date() })
    .where("id", "=", req.params.id)
    .execute();

  logger.info({ event: "scan_job.dismissed", scan_job_id: req.params.id, dismissed_by: req.session.username });
  recordAudit("scan_job.dismissed", req.session.username, req.ip, { scan_job_id: req.params.id });

  res.status(204).end();
}));

// Requests that a running job stop. Only ever honored for cancellable
// jobs (created by a long-running "serve" process - see
// ScanJobsTable.cancellable) since only those run the concurrent watcher
// that checks cancel_requested_at while the scan is in progress; a
// one-shot "scan"/"menu" process has nothing polling during its single
// blocking scan and would never notice. This only sets a flag - the
// scanner reports the actual outcome itself via PATCH
// /api/ingest/scan-jobs/:id once it's finished (or been killed), same
// as any other completion. Same operator-level access as dismiss/rescan.
scanJobsRouter.post("/:id/cancel", requireOperator, asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }

  const allowed = getAllowedScannerAgentIds(req);
  if (allowed) {
    const job = await db.selectFrom("scan_jobs").select(["scanner_agent_id"]).where("id", "=", req.params.id).executeTakeFirst();
    if (!job || !job.scanner_agent_id || !allowed.includes(job.scanner_agent_id)) {
      res.status(404).json({ error: "scan job not found" });
      return;
    }
  }

  const outcome = await requestScanCancel(singleParam(req.params.id));
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({ event: "scan_job.cancel_requested", scan_job_id: req.params.id, requested_by: req.session.username });
  recordAudit("scan_job.cancel_requested", req.session.username, req.ip, { scan_job_id: req.params.id });

  res.status(204).end();
}));
