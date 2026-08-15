import { db } from "./db";
import { logger } from "./logger";
import { recordAudit } from "./audit/log";
import { getAppSettings } from "./settings/appSettings";

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
 * no-op that still returns {purged: 0} rather than deleting everything).
 * masscan only reports hosts it finds with at least one open port, so a
 * host that's gone quiet simply stops appearing in scan results and its
 * last_seen_at freezes - there's no separate "still alive but portless"
 * signal to account for. ON DELETE CASCADE on host_port_observations,
 * screenshots, rdp_screenshots, tls_certificates, ssh_host_keys, host_tags,
 * and host_comments means deleting the host row takes all of its history
 * with it; scan_requests.host_id is ON DELETE SET NULL instead, so queue
 * rows survive with the host reference cleared.
 *
 * Called both by the hourly ticker above and by the Settings page's
 * manual trigger (POST /api/settings/retention/run-now) - one shared
 * implementation so an on-demand cleanup can never behave differently
 * from what the scheduled sweep would have done.
 */
export async function runRetentionSweep(): Promise<{ purged: number }> {
  const { hostRetentionDays } = await getAppSettings();
  if (hostRetentionDays <= 0) return { purged: 0 };

  const threshold = new Date(Date.now() - hostRetentionDays * 24 * 60 * 60_000);

  const stale = await db
    .selectFrom("hosts")
    .select(["id", "ip", "hostname", "last_seen_at"])
    .where("last_seen_at", "<", threshold)
    .execute();

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

  if (stale.length > 0) {
    logger.info({ event: "retention.sweep_completed", purged_count: stale.length, retention_days: hostRetentionDays });
  }

  return { purged: stale.length };
}
