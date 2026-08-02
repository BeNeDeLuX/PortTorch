import { db } from "../db";
import { logger } from "../logger";
import { dispatchWebhook } from "./dispatch";

const CHECK_INTERVAL_MS = 60 * 60_000; // hourly - unlike scan schedules, cert expiry only changes over days
const EXPIRY_WARNING_DAYS = 30;

/**
 * Periodically checks for TLS certificates within EXPIRY_WARNING_DAYS of
 * expiry and fires a certificate.expiring_soon webhook once per
 * certificate row (tracked via expiry_alert_sent_at, so it isn't
 * re-sent every hour for the same cert - a renewed cert gets a new row
 * with its own alert state).
 */
export function startCertificateExpiryAlerts(): void {
  setInterval(() => {
    tick().catch((err) =>
      logger.error({ event: "webhook.expiry_check_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const warningThreshold = new Date(Date.now() + EXPIRY_WARNING_DAYS * 24 * 60 * 60_000);

  const expiring = await db
    .selectFrom("tls_certificates")
    .innerJoin("hosts", "hosts.id", "tls_certificates.host_id")
    .select([
      "tls_certificates.id as id",
      "tls_certificates.port as port",
      "tls_certificates.not_after as not_after",
      "tls_certificates.subject_cn as subject_cn",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
    ])
    .where("tls_certificates.not_after", "<=", warningThreshold)
    .where("tls_certificates.expiry_alert_sent_at", "is", null)
    .execute();

  for (const cert of expiring) {
    const target = cert.host_hostname || cert.host_ip;
    const message = `TLS certificate for ${target}:${cert.port} (${cert.subject_cn ?? "no CN"}) expires ${
      cert.not_after ? new Date(cert.not_after).toISOString().slice(0, 10) : "soon"
    }`;

    await dispatchWebhook("certificate.expiring_soon", message, {
      host_ip: cert.host_ip,
      host_hostname: cert.host_hostname,
      port: cert.port,
      subject_cn: cert.subject_cn,
      not_after: cert.not_after,
    });

    await db
      .updateTable("tls_certificates")
      .set({ expiry_alert_sent_at: new Date() })
      .where("id", "=", cert.id)
      .execute();

    logger.info({ event: "webhook.certificate_expiry_alerted", tls_certificate_id: cert.id, host_ip: cert.host_ip, port: cert.port });
  }
}
