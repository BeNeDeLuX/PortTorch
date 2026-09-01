import nodemailer, { Transporter } from "nodemailer";
import { SmtpSettings, getAppSettings } from "../settings/appSettings";
import { caBundle } from "../settings/caCertificates";

// Built lazily and cached - undefined means "not built yet", null means
// "SMTP isn't configured" (a valid, expected state for a deployment that
// only ever uses webhook channels). Distinguishing those two rather than
// re-checking on every call avoids re-running nodemailer's own transport
// validation per send.
//
// The settings now live in app_settings rather than env vars, so unlike
// before this cache can go stale while the process is running: an admin
// fixing a mail server from the Settings page would otherwise keep
// hitting the old transport until the next restart, which is exactly the
// redeploy loop moving the settings into the database was meant to end.
// resetSmtpTransporter() is called from the settings route on every save.
let transporter: Transporter | null | undefined;

export function resetSmtpTransporter(): void {
  transporter = undefined;
}

// ca is the admin-uploaded trust anchors plus Node's own public roots
// (see caCertificates.ts on why both). Passed through rather than fetched
// here so this stays a pure function - the SMTP test route builds its own
// transporter from the same pair.
export function buildTransporter(smtp: SmtpSettings, ca?: string[]): Transporter | null {
  if (!smtp.host) return null;
  return nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    // STARTTLS (the common case on 587) is negotiated after connect
    // regardless of this flag; `secure: true` is only for implicit-TLS
    // ports like 465 - matches nodemailer's own documented behavior.
    secure: smtp.secure,
    auth: smtp.user ? { user: smtp.user, pass: smtp.password ?? undefined } : undefined,
    // Applies to both implicit TLS and a STARTTLS upgrade, so turning
    // verification off works on 587 as well as 465 - which is the case
    // that actually comes up, since an internal relay on 587 with a
    // private-CA certificate fails with "self-signed certificate in
    // certificate chain" and no other way past it.
    tls: { rejectUnauthorized: smtp.verifyTls, ...(ca ? { ca } : {}) },
  });
}

async function getTransporter(): Promise<{ transport: Transporter | null; smtp: SmtpSettings }> {
  const { smtp } = await getAppSettings();
  if (transporter === undefined) {
    transporter = buildTransporter(smtp, await caBundle());
  }
  return { transport: transporter, smtp };
}

export function senderAddress(smtp: SmtpSettings): string {
  return smtp.from || smtp.user || "porttorch@localhost";
}

// `to` is a comma-joined recipient list (webhooks.email_to, see db/types.ts)
// - nodemailer accepts that directly, no need to split it ourselves.
export async function sendEmailAlert(to: string, subject: string, text: string): Promise<void> {
  const { transport, smtp } = await getTransporter();
  if (!transport) {
    // The wording matters: dispatchWebhook classifies this exact message
    // as a permanent failure so unconfigured SMTP doesn't build a retry
    // backlog (see webhooks/dispatch.ts's attemptDelivery).
    throw new Error("SMTP is not configured (set a mail server under Admin -> Settings)");
  }
  await transport.sendMail({ from: senderAddress(smtp), to, subject, text });
}
