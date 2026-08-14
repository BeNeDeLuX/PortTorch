import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";
import { getCurrentCertInfo } from "../tls/certUpload";

// Same hourly cadence and 30-day warning window as webhooks/expiryAlerts.ts
// (which covers *scanned hosts'* certificates) - this covers the
// webserver's own TLS listener certificate instead, a single filesystem
// artifact rather than a database table of many, so it needs its own
// singleton alert-dedup state (webserver_tls_alert_state) rather than a
// per-row expiry_alert_sent_at column.
const CHECK_INTERVAL_MS = 60 * 60_000;
const EXPIRY_WARNING_DAYS = 30;

export function startWebserverCertExpiryAlert(): void {
  setInterval(() => {
    tick().catch((err) =>
      logger.error({
        event: "webhook.webserver_cert_expiry_check_failed",
        err: err instanceof Error ? err.message : String(err),
      })
    );
  }, CHECK_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const info = getCurrentCertInfo(config.certDir);
  const warningThreshold = new Date(Date.now() + EXPIRY_WARNING_DAYS * 24 * 60 * 60_000);
  if (new Date(info.validTo).getTime() > warningThreshold.getTime()) {
    return;
  }

  const state = await db
    .selectFrom("webserver_tls_alert_state")
    .select(["fingerprint"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();

  // Already alerted for this exact certificate - a renewed/replaced
  // certificate (Settings page upload) gets a different fingerprint and
  // is therefore treated as never-yet-alerted, same as a brand new
  // tls_certificates row would be.
  if (state.fingerprint === info.fingerprint256) {
    return;
  }

  const message = `The webserver's own TLS certificate (${info.subjectCN ?? "no CN"}) expires ${new Date(
    info.validTo
  )
    .toISOString()
    .slice(0, 10)}`;

  await dispatchWebhook("webserver_certificate.expiring_soon", message, {
    subject_cn: info.subjectCN,
    issuer_cn: info.issuerCN,
    valid_to: info.validTo,
    self_signed: info.selfSigned,
  });

  await db
    .updateTable("webserver_tls_alert_state")
    .set({ fingerprint: info.fingerprint256, alert_sent_at: new Date() })
    .where("id", "=", 1)
    .execute();

  logger.info({
    event: "webhook.webserver_cert_expiry_alerted",
    subject_cn: info.subjectCN,
    valid_to: info.validTo,
  });
}
