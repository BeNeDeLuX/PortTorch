import { sql } from "kysely";
import { config } from "../config";
import { db } from "../db";
import { isStaleScanJob } from "../lib/staleness";
import { logger } from "../logger";
import { dispatchWebhook } from "./dispatch";
import { getAppSettings } from "../settings/appSettings";

// Far more frequent than the hourly certificate-expiry checks
// (webhooks/expiryAlerts.ts, settings/certExpiryAlert.ts) - unlike a
// slow-moving expiry countdown, a scan that's died mid-run or a queue
// that's stopped draining is actionable right away, not just "worth
// knowing about sometime today".
const CHECK_INTERVAL_MS = 5 * 60_000;

// The Fleet Health page (frontend/src/pages/FleetHealth.tsx) surfaces
// these same two conditions passively, for whoever happens to load that
// page - this is the active counterpart, pushing scan.stale and
// scan_queue.backlog webhooks so nobody has to be looking.
export function startOperationalAlerts(): void {
  setInterval(() => {
    tick().catch((err) =>
      logger.error({ event: "webhook.operational_check_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}

async function tick(): Promise<void> {
  await checkStaleScans();
  await checkQueueBacklog();
}

// Fires scan.stale once per scan_jobs row (stale_alert_sent_at) - a job
// stuck in "running" past app_settings.stale_scan_threshold_minutes with
// no recent progress heartbeat almost always means the scanner process
// died mid-scan (see lib/staleness.ts's isStaleScanJob and the existing
// is_stale flag on GET /api/scan-jobs/active - same activity-aware check,
// so this never fires for a scan that's merely slow but still genuinely
// progressing). No need to ever clear the flag: a scan_jobs row is
// created fresh per scan and either finishes normally (leaving the
// "running" status this query filters on) or stays stuck forever, so
// "fire once, forever" is correct here, same idiom as
// tls_certificates.expiry_alert_sent_at.
async function checkStaleScans(): Promise<void> {
  const candidates = await db
    .selectFrom("scan_jobs")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .leftJoin("scan_job_progress", "scan_job_progress.scan_job_id", "scan_jobs.id")
    .select([
      "scan_jobs.id as id",
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scan_jobs.started_at as started_at",
      "scanner_agents.name as scanner_agent_name",
      "scan_job_progress.updated_at as last_progress_at",
    ])
    .where("scan_jobs.status", "=", "running")
    .where("scan_jobs.stale_alert_sent_at", "is", null)
    .execute();
  const { staleScanThresholdMinutes } = await getAppSettings();

  for (const job of candidates) {
    if (!isStaleScanJob(job.started_at, job.last_progress_at, staleScanThresholdMinutes)) continue;

    const scannerLabel = job.scanner_agent_name ?? "an unknown scanner";
    const message = `Scan job on ${scannerLabel} targeting ${job.target_spec}:${job.port_spec} looks stalled - still "running" since ${new Date(job.started_at).toISOString()}`;

    await dispatchWebhook("scan.stale", message, {
      scan_job_id: job.id,
      scanner_agent_name: job.scanner_agent_name,
      target_spec: job.target_spec,
      port_spec: job.port_spec,
      started_at: job.started_at,
    });

    await db.updateTable("scan_jobs").set({ stale_alert_sent_at: new Date() }).where("id", "=", job.id).execute();
    logger.info({ event: "webhook.scan_stale_alerted", scan_job_id: job.id });
  }
}

// Fires scan_queue.backlog once per scanner agent whose oldest pending
// scan_requests row is older than config.queueBacklogThresholdMinutes -
// tracked on scanner_agents.queue_backlog_alert_sent_at (one flag per
// agent, not per request), since the backlog is one ongoing condition for
// that scanner, not N independent events. Unlike checkStaleScans above,
// this condition can come and go (the scanner catches up, then falls
// behind again later), so the flag is actively cleared once that agent no
// longer has an aged backlog - letting a future backlog alert again
// instead of being permanently silenced by one past incident.
async function checkQueueBacklog(): Promise<void> {
  const threshold = new Date(Date.now() - config.queueBacklogThresholdMinutes * 60_000);

  const backlogged = await db
    .selectFrom("scan_requests")
    .innerJoin("scanner_agents", "scanner_agents.id", "scan_requests.scanner_agent_id")
    .select([
      "scan_requests.scanner_agent_id as scanner_agent_id",
      "scanner_agents.name as scanner_agent_name",
      "scanner_agents.queue_backlog_alert_sent_at as queue_backlog_alert_sent_at",
      sql<number>`count(*)`.as("pending_count"),
      sql<Date>`min(scan_requests.created_at)`.as("oldest_created_at"),
    ])
    .where("scan_requests.status", "=", "pending")
    .where("scanner_agents.revoked_at", "is", null)
    .groupBy(["scan_requests.scanner_agent_id", "scanner_agents.name", "scanner_agents.queue_backlog_alert_sent_at"])
    .execute();

  const stillBackloggedIds: string[] = [];

  for (const row of backlogged) {
    if (new Date(row.oldest_created_at) > threshold) continue;
    // scan_requests.scanner_agent_id is nullable in general (a request
    // whose agent was later deleted), but the innerJoin on scanner_agents
    // above means every row here necessarily has one.
    stillBackloggedIds.push(row.scanner_agent_id!);
    if (row.queue_backlog_alert_sent_at) continue; // already alerted, still backlogged - don't repeat

    const pendingCount = Number(row.pending_count);
    const message = `Scanner "${row.scanner_agent_name}" has ${pendingCount} pending scan request(s) queued, oldest queued since ${new Date(row.oldest_created_at).toISOString()} - it may have stopped polling`;

    await dispatchWebhook("scan_queue.backlog", message, {
      scanner_agent_id: row.scanner_agent_id,
      scanner_agent_name: row.scanner_agent_name,
      pending_count: pendingCount,
      oldest_created_at: row.oldest_created_at,
    });

    await db
      .updateTable("scanner_agents")
      .set({ queue_backlog_alert_sent_at: new Date() })
      .where("id", "=", row.scanner_agent_id)
      .execute();
    logger.info({ event: "webhook.queue_backlog_alerted", scanner_agent_id: row.scanner_agent_id });
  }

  // Clear any previously-alerted agent that's no longer in the
  // still-backlogged set above (caught up, or its aged requests were
  // cancelled/claimed/deleted) - an empty exclusion list needs its own
  // branch since a plain "id not in ()" is invalid SQL.
  let clearQuery = db
    .updateTable("scanner_agents")
    .set({ queue_backlog_alert_sent_at: null })
    .where("queue_backlog_alert_sent_at", "is not", null);
  if (stillBackloggedIds.length > 0) {
    clearQuery = clearQuery.where("id", "not in", stillBackloggedIds);
  }
  await clearQuery.execute();
}
