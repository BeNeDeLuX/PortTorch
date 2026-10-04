import { db } from "../db";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { targetSpecSchema } from "../lib/targetSpec";

export type ResumeOutcome =
  | { ok: true; scanRequestId: string; targetSpec: string; portSpec: string; scannerAgentId: string; scannerAgentName: string }
  | { ok: false; status: 400 | 404 | 409; error: string };

// Queues what a cancelled or failed scan never finished, as a new scan
// request on the same scanner with the same ports. Not a pause/resume of
// the original: masscan and nmap run as separate processes and a stateless
// SYN scanner that is frozen loses every reply that arrives meanwhile, so
// "resume" means "scan the rest" - which the scanner can state precisely,
// because it discovers large targets in blocks and knows which blocks and
// hosts it finished (see migration 1746700000000).
//
// The original request's settings - scan profile, nuclei profile, rate,
// priority, tags - are carried over, unlike Scan History's Rescan button:
// this finishes *that* scan, so running the rest with different scripts
// would produce a result nobody asked for. They come from the snapshot on
// the originating scan_requests row, so an edited or deleted profile
// changes nothing. A job with no originating request (started from the
// scanner's own local API) resumes with defaults.
//
// A share of a split scan stays a share of it: the new request joins the
// same group as the same part, so the group's own view lists the resume
// beside the part it finishes.
//
// Shared by the single-job resume and the resume-every-part action on a
// split scan, so the two cannot disagree about what is resumable.
export async function resumeScanJob(
  jobId: string,
  allowedScannerAgentIds: string[] | null,
  actor: { username: string | undefined; ip: string | undefined }
): Promise<ResumeOutcome> {
  const job = await db
    .selectFrom("scan_jobs")
    .select(["id", "status", "scanner_agent_id", "port_spec", "remaining_target_spec", "resumed_at"])
    .where("id", "=", jobId)
    .executeTakeFirst();
  if (!job || (allowedScannerAgentIds && (!job.scanner_agent_id || !allowedScannerAgentIds.includes(job.scanner_agent_id)))) {
    return { ok: false, status: 404, error: "scan job not found" };
  }
  if (job.status === "running" || job.status === "completed" || !job.remaining_target_spec) {
    return { ok: false, status: 409, error: "this scan has nothing left to resume" };
  }
  if (job.resumed_at) return { ok: false, status: 409, error: "this scan has already been resumed" };
  if (!job.scanner_agent_id) return { ok: false, status: 409, error: "the scanner that ran this scan has been deleted" };
  const scannerAgentId = job.scanner_agent_id;

  const agent = await db.selectFrom("scanner_agents").select(["name", "revoked_at"]).where("id", "=", scannerAgentId).executeTakeFirst();
  if (!agent || agent.revoked_at) return { ok: false, status: 409, error: "the scanner that ran this scan has been revoked" };

  // The remainder of a huge scan can in principle outgrow what one masscan
  // argument can carry, which is exactly the limit targetSpecSchema
  // enforces for a typed target. Refusing here says so before anything is
  // queued, rather than letting the scanner fail on it later.
  const spec = targetSpecSchema.safeParse(job.remaining_target_spec);
  if (!spec.success) {
    return {
      ok: false,
      status: 400,
      error: "what is left of this scan is too long to queue as one scan - split the remaining target across several ad-hoc scans",
    };
  }

  const origin = await db
    .selectFrom("scan_requests")
    .select([
      "nse_profile",
      "nse_scripts",
      "nse_profile_label",
      "nuclei_profile",
      "nuclei_tags",
      "nuclei_profile_label",
      "masscan_rate",
      "priority",
      "tags",
      "scan_group_id",
      "group_part",
      "group_parts",
    ])
    .where("scan_job_id", "=", jobId)
    .orderBy("created_at", "desc")
    .executeTakeFirst();

  const created = await db.transaction().execute(async (trx) => {
    // Compare-and-set, so two operators clicking at once queue the rest
    // once, not twice.
    const claimed = await trx
      .updateTable("scan_jobs")
      .set({ resumed_at: new Date().toISOString() })
      .where("id", "=", jobId)
      .where("resumed_at", "is", null)
      .returning(["id"])
      .executeTakeFirst();
    if (!claimed) return null;

    const request = await trx
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: scannerAgentId,
        host_id: null,
        target_spec: spec.data,
        port_spec: job.port_spec,
        requested_by: actor.username ?? null,
        ...(origin
          ? {
              nse_profile: origin.nse_profile,
              nse_scripts: origin.nse_scripts,
              nse_profile_label: origin.nse_profile_label,
              nuclei_profile: origin.nuclei_profile,
              nuclei_tags: origin.nuclei_tags,
              nuclei_profile_label: origin.nuclei_profile_label,
              masscan_rate: origin.masscan_rate,
              priority: origin.priority,
              tags: origin.tags,
              scan_group_id: origin.scan_group_id,
              group_part: origin.group_part,
              group_parts: origin.group_parts,
            }
          : {}),
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    await trx.updateTable("scan_jobs").set({ resumed_scan_request_id: request.id }).where("id", "=", jobId).execute();
    return request;
  });
  if (!created) return { ok: false, status: 409, error: "this scan has already been resumed" };

  logger.info({
    event: "scan_job.resumed",
    scan_job_id: jobId,
    scan_request_id: created.id,
    scan_group_id: origin?.scan_group_id ?? null,
    scanner_agent_id: scannerAgentId,
    scanner_agent_name: agent.name,
    remaining_target_spec: spec.data,
    port_spec: job.port_spec,
    requested_by: actor.username,
    source_ip: actor.ip,
  });
  recordAudit("scan_job.resumed", actor.username, actor.ip, {
    scan_job_id: jobId,
    scan_request_id: created.id,
    scanner_agent_id: scannerAgentId,
  });

  return { ok: true, scanRequestId: created.id, targetSpec: spec.data, portSpec: job.port_spec, scannerAgentId, scannerAgentName: agent.name };
}
