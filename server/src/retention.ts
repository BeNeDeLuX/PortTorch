import { config } from "./config";
import { db } from "./db";
import { logger } from "./logger";
import { recordAudit } from "./audit/log";

const CHECK_INTERVAL_MS = 60 * 60_000; // hourly, like the cert expiry check - retention doesn't need finer granularity

/**
 * Purges hosts whose last_seen_at is older than config.hostRetentionDays.
 * masscan only reports hosts it finds with at least one open port, so a
 * host that's gone quiet simply stops appearing in scan results and its
 * last_seen_at freezes - there's no separate "still alive but portless"
 * signal to account for. ON DELETE CASCADE on host_port_observations,
 * screenshots, rdp_screenshots, tls_certificates, ssh_host_keys, host_tags,
 * and host_comments means deleting the host row takes all of its history
 * with it; scan_requests.host_id is ON DELETE SET NULL instead, so queue
 * rows survive with the host reference cleared.
 */
export function startRetention(): void {
  if (config.hostRetentionDays <= 0) return;
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "retention.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, CHECK_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const threshold = new Date(Date.now() - config.hostRetentionDays * 24 * 60 * 60_000);

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
    logger.info({ event: "retention.sweep_completed", purged_count: stale.length, retention_days: config.hostRetentionDays });
  }
}
