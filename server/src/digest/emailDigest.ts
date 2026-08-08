import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";
import { computeDigest, DigestResult } from "./routes";

// Hourly, same cadence as webhooks/expiryAlerts.ts - fine-grained enough to
// land within the configured hour without checking every minute for a
// once-a-day event.
const CHECK_INTERVAL_MS = 60 * 60_000;

export function startDailyDigestEmail(): void {
  tick().catch((err) => logger.error({ event: "digest_email.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "digest_email.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, CHECK_INTERVAL_MS);
}

// node-postgres's default type parser returns a Postgres `date` column as
// a JS Date (midnight UTC), not the plain "YYYY-MM-DD" string it was
// written as - confirmed by testing, not assumed: comparing it directly
// against a string via `===` silently never matches, which is exactly the
// bug this normalization exists to avoid (the "already sent today" guard
// below would otherwise never trigger, re-sending on every hourly tick
// throughout the configured hour).
function toDateOnlyString(value: Date | string | null): string | null {
  if (value === null) return null;
  return (value instanceof Date ? value : new Date(value)).toISOString().slice(0, 10);
}

// Exported so tests can invoke a single tick directly against a real
// database/config rather than waiting on the hourly setInterval (see
// digestEmail.integration.test.ts).
export async function tick(): Promise<void> {
  const now = new Date();
  if (now.getUTCHours() !== config.digestEmailHourUtc) return;

  const todayUtc = now.toISOString().slice(0, 10);
  const state = await db.selectFrom("digest_email_state").select(["last_sent_date"]).where("id", "=", 1).executeTakeFirst();
  // Persisted (not in-memory) specifically so a webserver restart that
  // happens to land within the configured hour, after already having sent
  // today, can't fire a second time - same reasoning as
  // tls_certificates.expiry_alert_sent_at / scan_schedules.last_run_at.
  if (toDateOnlyString(state?.last_sent_date ?? null) === todayUtc) return;

  // No fleet-wide scanner restriction here - unlike a session-scoped
  // request, this is a background job with no user attached, so it always
  // covers every scanner (allowedScannerAgentIds: null), same as
  // savedSearches/checker.ts's periodic check.
  const to = now;
  const from = new Date(to.getTime() - 24 * 60 * 60_000);
  const digest = await computeDigest(from, to, null);

  await dispatchWebhook("digest.daily", formatDigestEmail(digest), { digest });

  await db
    .insertInto("digest_email_state")
    .values({ id: 1, last_sent_date: todayUtc })
    .onConflict((oc) => oc.column("id").doUpdateSet({ last_sent_date: todayUtc }))
    .execute();

  logger.info({
    event: "digest_email.sent",
    new_hosts: digest.newHosts.length,
    changed_hosts: digest.changedHosts.length,
  });
}

// Plain text - sendEmailAlert (webhooks/email.ts) has no HTML body option,
// and a webhook channel subscribed to the same "digest.daily" event
// renders whatever's passed as dispatchWebhook's "message" too (Slack/
// Discord incoming webhooks display it as-is), so one plain-text format
// serves both channel types rather than needing an email-specific one.
function formatDigestEmail(digest: DigestResult): string {
  const lines: string[] = [`PortTorch daily digest — ${digest.from} to ${digest.to}`, ""];

  if (digest.newHosts.length === 0 && digest.changedHosts.length === 0) {
    lines.push("No new hosts or port changes in the last 24 hours.");
    return lines.join("\n");
  }

  if (digest.newHosts.length > 0) {
    lines.push(`New hosts (${digest.newHosts.length}):`);
    for (const h of digest.newHosts) {
      const label = h.hostname ? `${h.hostname} (${h.ip})` : h.ip;
      lines.push(`  - ${label}${h.scannerAgentName ? ` via ${h.scannerAgentName}` : ""}`);
    }
    lines.push("");
  }

  if (digest.changedHosts.length > 0) {
    lines.push(`Changed hosts (${digest.changedHosts.length}):`);
    for (const h of digest.changedHosts) {
      const label = h.hostname ? `${h.hostname} (${h.ip})` : h.ip;
      const parts: string[] = [];
      if (h.newlyOpen.length > 0) parts.push(`+${h.newlyOpen.map((p) => p.port).join(",")}`);
      if (h.newlyClosed.length > 0) parts.push(`-${h.newlyClosed.map((p) => p.port).join(",")}`);
      lines.push(`  - ${label}: ${parts.join(" ")}`);
    }
  }

  return lines.join("\n");
}
