import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { singleParam } from "../lib/reqParams";
import { resumeScanJob } from "../scanJobs/resume";

export const scanGroupsRouter = Router();
scanGroupsRouter.use(requireAuth);

// What one attempt at a part is doing, in the words the dashboard uses.
// A request is queued until a scanner claims it and running until that
// scanner reports back; after that its own terminal status is the answer.
type AttemptState = "queued" | "running" | "completed" | "failed" | "cancelled";

function attemptState(requestStatus: string): AttemptState {
  if (requestStatus === "pending") return "queued";
  if (requestStatus === "claimed") return "running";
  if (requestStatus === "completed" || requestStatus === "failed" || requestStatus === "cancelled") return requestStatus;
  return "queued";
}

interface AttemptRow {
  id: string;
  scanner_agent_id: string | null;
  scanner_agent_name: string | null;
  target_spec: string;
  status: string;
  group_part: number | null;
  created_at: Date;
  completed_at: Date | null;
  scan_job_id: string | null;
  remaining_target_spec: string | null;
  resumed_at: Date | null;
  hosts_scanned: string | number | null;
  open_ports_found: string | number | null;
}

async function loadGroup(id: string, allowed: string[] | null) {
  const group = await db.selectFrom("scan_groups").selectAll().where("id", "=", id).executeTakeFirst();
  if (!group) return null;

  const { rows } = await sql<AttemptRow>`
    SELECT sr.id, sr.scanner_agent_id, sa.name AS scanner_agent_name, sr.target_spec, sr.status,
           sr.group_part, sr.created_at, sr.completed_at, sr.scan_job_id,
           sj.remaining_target_spec, sj.resumed_at,
           (SELECT count(DISTINCT host_id) FROM host_port_observations WHERE scan_job_id = sr.scan_job_id) AS hosts_scanned,
           (SELECT count(*) FROM host_port_observations WHERE scan_job_id = sr.scan_job_id AND state = 'open') AS open_ports_found
    FROM scan_requests sr
    LEFT JOIN scanner_agents sa ON sa.id = sr.scanner_agent_id
    LEFT JOIN scan_jobs sj ON sj.id = sr.scan_job_id
    WHERE sr.scan_group_id = ${id}
    ORDER BY sr.group_part, sr.created_at
  `.execute(db);

  // A restricted session sees a split scan only if it may see every
  // scanner in it. Showing it partially would still reveal the others'
  // shares of the target; 404 rather than 403, so its existence is not
  // confirmed either - the rule every scan-job route here follows.
  if (allowed && group.scanner_agent_ids.some((sid) => !allowed.includes(sid))) return null;

  const parts = new Map<number, AttemptRow[]>();
  for (const row of rows) {
    const part = row.group_part ?? 0;
    parts.set(part, [...(parts.get(part) ?? []), row]);
  }

  const partViews = [...parts.entries()]
    .sort(([a], [b]) => a - b)
    .map(([part, attempts]) => {
      const latest = attempts[attempts.length - 1];
      const state = attemptState(latest.status);
      return {
        part,
        scannerAgentId: latest.scanner_agent_id,
        scannerAgentName: latest.scanner_agent_name,
        state,
        // Resumable: the last attempt stopped early, reported what it never
        // finished, and nobody has queued that remainder yet.
        resumable:
          (state === "cancelled" || state === "failed") &&
          latest.scan_job_id !== null &&
          latest.remaining_target_spec !== null &&
          latest.resumed_at === null,
        attempts: attempts.map((a) => ({
          scanRequestId: a.id,
          scanJobId: a.scan_job_id,
          targetSpec: a.target_spec,
          state: attemptState(a.status),
          createdAt: a.created_at,
          completedAt: a.completed_at,
          remainingTargetSpec: a.remaining_target_spec,
          // Counted from what landed in the database, like every other
          // per-scan figure here - and Number()-converted, since count()
          // is a bigint node-postgres returns as a string.
          hostsScanned: a.scan_job_id ? Number(a.hosts_scanned ?? 0) : null,
          openPortsFound: a.scan_job_id ? Number(a.open_ports_found ?? 0) : null,
        })),
      };
    });

  const count = (s: AttemptState) => partViews.filter((p) => p.state === s).length;
  // One word for the whole scan. Still running while any part is queued or
  // running; complete only when every part's latest attempt completed;
  // otherwise it ended with something unfinished.
  const status =
    count("queued") + count("running") > 0 ? "running" : count("completed") === partViews.length ? "completed" : "incomplete";

  return {
    id: group.id,
    targetSpec: group.target_spec,
    portSpec: group.port_spec,
    parts: group.parts,
    masscanRateSplit: group.masscan_rate_split,
    requestedBy: group.requested_by,
    scheduleId: group.schedule_id,
    createdAt: group.created_at,
    status,
    counts: {
      queued: count("queued"),
      running: count("running"),
      completed: count("completed"),
      failed: count("failed"),
      cancelled: count("cancelled"),
      resumable: partViews.filter((p) => p.resumable).length,
    },
    partViews,
  };
}

// A split scan as a whole: every share, each one's attempts (the original
// and any resume of it), and one status for the lot. Scan History lists the
// shares as separate jobs, which on its own never answers "is this scan
// done?". Same read access as the history it opens from.
scanGroupsRouter.get("/:id", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan group id" });
    return;
  }
  const group = await loadGroup(singleParam(req.params.id), getAllowedScannerAgentIds(req));
  if (!group) {
    res.status(404).json({ error: "scan group not found" });
    return;
  }
  res.json(group);
}));

// Resumes every share of a split scan that stopped early, in one action -
// each exactly as the single-job Resume would (resume.ts), so the two can
// never disagree about what is resumable. A share that cannot be resumed
// (its scanner since revoked, say) is reported, not fatal: the others
// still go ahead.
scanGroupsRouter.post("/:id/resume", requireOperator, asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan group id" });
    return;
  }
  const allowed = getAllowedScannerAgentIds(req);
  const group = await loadGroup(singleParam(req.params.id), allowed);
  if (!group) {
    res.status(404).json({ error: "scan group not found" });
    return;
  }
  const resumable = group.partViews.filter((p) => p.resumable);
  if (resumable.length === 0) {
    res.status(409).json({ error: "no part of this scan has anything left to resume" });
    return;
  }

  const results = [];
  for (const part of resumable) {
    const jobId = part.attempts[part.attempts.length - 1].scanJobId!;
    const outcome = await resumeScanJob(jobId, allowed, { username: req.session.username, ip: req.ip });
    results.push({ part: part.part, ...(outcome.ok ? { ok: true, scanRequestId: outcome.scanRequestId } : { ok: false, error: outcome.error }) });
  }
  res.status(201).json({ results });
}));
