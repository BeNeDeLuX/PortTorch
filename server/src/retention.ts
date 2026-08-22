import { db } from "./db";
import { logger } from "./logger";
import { recordAudit } from "./audit/log";
import { getAppSettings } from "./settings/appSettings";
import {
  deleteScreenshotFiles,
  purgeOldScreenshots,
  purgeOrphanedScreenshotFiles,
  screenshotPathsForHosts,
} from "./screenshots/files";

const CHECK_INTERVAL_MS = 60 * 60_000; // hourly, like the cert expiry check - retention doesn't need finer granularity

/**
 * Starts the hourly background sweep - see runRetentionSweep for the
 * actual purge logic, shared with the Settings page's manual "Clean up
 * now" button so both trigger the exact same thing.
 */
export function startRetention(): void {
  setInterval(() => {
    runRetentionSweep().catch((err) =>
      logger.error({ event: "retention.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}

/**
 * Purges hosts whose last_seen_at is older than the current
 * app_settings.host_retention_days (admin-editable from the Settings
 * page - see settings/appSettings.ts; 0 disables the sweep entirely, a
 * no-op that still returns {purgedHosts: 0, purgedAuditLogEntries: 0}
 * rather than deleting everything). masscan only reports hosts it finds
 * with at least one open port, so a host that's gone quiet simply stops
 * appearing in scan results and its last_seen_at freezes - there's no
 * separate "still alive but portless" signal to account for. ON DELETE
 * CASCADE on host_port_observations, screenshots, rdp_screenshots,
 * tls_certificates, ssh_host_keys, host_tags, and host_comments means
 * deleting the host row takes all of its history with it;
 * scan_requests.host_id is ON DELETE SET NULL instead, so queue rows
 * survive with the host reference cleared.
 *
 * Also purges audit_log rows older than the same window - unlike
 * webhook_deliveries (trimmed to a fixed count per webhook at insert
 * time, a diagnostic tail, not a record), audit_log used to be kept
 * forever with no pruning at all; tying it to the same admin-editable
 * host_retention_days window (rather than a second, separate setting)
 * keeps "how long do we keep history" a single knob instead of two that
 * could drift out of sync with each other.
 *
 * Called both by the hourly ticker above and by the Settings page's
 * manual trigger (POST /api/settings/retention/run-now) - one shared
 * implementation so an on-demand cleanup can never behave differently
 * from what the scheduled sweep would have done.
 */
export async function runRetentionSweep(): Promise<{
  purgedHosts: number;
  purgedAuditLogEntries: number;
  purgedScanLogs: number;
  purgedScreenshots: number;
}> {
  const { hostRetentionDays, scanLogRetentionDays } = await getAppSettings();

  // The two windows are independent, so a deployment with the host sweep
  // disabled (hostRetentionDays 0, a supported configuration) still gets
  // its scan logs bounded - folding them under the same early return
  // would quietly reintroduce the unbounded growth this fixes.
  const purgedScanLogs = await purgeScanLogs(scanLogRetentionDays);

  // Runs regardless of the host window: these files are referenced by
  // nothing, so there is no history to preserve and no reason to keep
  // them even where retention is deliberately switched off.
  let purgedScreenshots = await purgeOrphanedScreenshotFiles();

  if (hostRetentionDays <= 0) return { purgedHosts: 0, purgedAuditLogEntries: 0, purgedScanLogs, purgedScreenshots };

  const threshold = new Date(Date.now() - hostRetentionDays * 24 * 60 * 60_000);

  const stale = await db
    .selectFrom("hosts")
    .select(["id", "ip", "hostname", "last_seen_at"])
    .where("last_seen_at", "<", threshold)
    .execute();

  // Collected before the delete: the cascade removes the screenshot rows
  // along with the host, and with them the only record of which files on
  // disk belonged to it.
  const staleScreenshotPaths = await screenshotPathsForHosts(stale.map((h) => h.id));

  for (const host of stale) {
    await db.deleteFrom("hosts").where("id", "=", host.id).execute();

    logger.info({ event: "retention.host_purged", host_id: host.id, host_ip: host.ip, last_seen_at: host.last_seen_at });
    await recordAudit("retention.host_purged", "retention", undefined, {
      host_id: host.id,
      host_ip: host.ip,
      hostname: host.hostname,
      last_seen_at: host.last_seen_at,
    });
  }

  purgedScreenshots += deleteScreenshotFiles(staleScreenshotPaths);

  // Age-based, for hosts that are still alive - otherwise only host
  // deletion would ever reclaim anything and a long-lived host scanned on
  // a schedule grows without limit. Same window as the host sweep.
  purgedScreenshots += await purgeOldScreenshots(threshold);

  if (stale.length > 0) {
    logger.info({ event: "retention.sweep_completed", purged_count: stale.length, retention_days: hostRetentionDays });
  }

  // Deliberately computed against the same "now" the host sweep above
  // used (threshold), not a fresh Date.now() - keeps both halves of this
  // one sweep referring to the exact same cutoff instant. Run after the
  // host purge so this sweep's own host.tag_added/retention.host_purged
  // entries from just above are themselves still subject to the same
  // window on the *next* run, same as any other audit entry.
  const auditPurgeResult = await db
    .deleteFrom("audit_log")
    .where("created_at", "<", threshold)
    .executeTakeFirst();
  const purgedAuditLogEntries = Number(auditPurgeResult.numDeletedRows);

  if (purgedAuditLogEntries > 0) {
    logger.info({ event: "retention.audit_log_purged", purged_count: purgedAuditLogEntries, retention_days: hostRetentionDays });
    await recordAudit("retention.audit_log_purged", "retention", undefined, {
      purged_count: purgedAuditLogEntries,
      retention_days: hostRetentionDays,
    });
  }

  return { purgedHosts: stale.length, purgedAuditLogEntries, purgedScanLogs, purgedScreenshots };
}

/**
 * Drops the pushed log output of finished scans past the window, while
 * deliberately keeping the scan_jobs row itself - Scan History stays
 * complete (target, duration, host/port counts, status), only the bulky
 * per-line log goes. That split is the point: the history is the record,
 * the log is a diagnostic.
 *
 * Both tables were previously unbounded. Nothing has ever deleted a
 * scan_jobs row, so their ON DELETE CASCADE never fired, and the
 * retention sweep only knew about hosts and audit_log. scan_job_progress
 * in particular is documented as holding "nothing worth keeping once the
 * job finishes" while being kept forever.
 *
 * Keyed on each row's own timestamp rather than a join to scan_jobs, plus
 * an explicit guard against jobs still running: scan_job_progress is
 * rewritten every few seconds for the whole duration of a scan, so a
 * stale updated_at already implies the scan is over, and
 * scan_job_full_log is only ever written once at the very end - but a
 * scan that outlives the window (a very large range) would otherwise
 * have its live progress deleted out from under the Details popup.
 */
async function purgeScanLogs(retentionDays: number): Promise<number> {
  if (retentionDays <= 0) return 0;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60_000);

  const notRunning = (eb: any) =>
    eb.not(
      eb.exists(
        eb
          .selectFrom("scan_jobs")
          .select("scan_jobs.id")
          .whereRef("scan_jobs.id", "=", "scan_job_progress.scan_job_id")
          .where("scan_jobs.status", "=", "running")
      )
    );

  const progress = await db
    .deleteFrom("scan_job_progress")
    .where("updated_at", "<", cutoff)
    .where(notRunning)
    .executeTakeFirst();

  const full = await db
    .deleteFrom("scan_job_full_log")
    .where("created_at", "<", cutoff)
    .where((eb) =>
      eb.not(
        eb.exists(
          eb
            .selectFrom("scan_jobs")
            .select("scan_jobs.id")
            .whereRef("scan_jobs.id", "=", "scan_job_full_log.scan_job_id")
            .where("scan_jobs.status", "=", "running")
        )
      )
    )
    .executeTakeFirst();

  const purged = Number(progress.numDeletedRows) + Number(full.numDeletedRows);
  if (purged > 0) {
    logger.info({
      event: "retention.scan_logs_purged",
      purged_progress_rows: Number(progress.numDeletedRows),
      purged_full_log_rows: Number(full.numDeletedRows),
      retention_days: retentionDays,
    });
    await recordAudit("retention.scan_logs_purged", "retention", undefined, {
      purged_count: purged,
      retention_days: retentionDays,
    });
  }
  return purged;
}
