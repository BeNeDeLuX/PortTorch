import nodemailer, { Transporter } from "nodemailer";
import { config } from "../config";

// Built lazily, once, and cached - undefined means "not built yet", null
// means "SMTP isn't configured" (a valid, expected state for a deployment
// that only ever uses webhook channels). Distinguishing those two rather
// than re-checking config.smtp.host on every call avoids re-running
// nodemailer's own transport validation on every send.
let transporter: Transporter | null | undefined;

function getTransporter(): Transporter | null {
  if (transporter !== undefined) return transporter;
  if (!config.smtp.host) {
    transporter = null;
    return transporter;
  }
  transporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.password } : undefined,
  });
  return transporter;
}

export function isSmtpConfigured(): boolean {
  return getTransporter() !== null;
}

// `to` is a comma-joined recipient list (webhooks.email_to, see db/types.ts)
// - nodemailer accepts that directly, no need to split it ourselves.
export async function sendEmailAlert(to: string, subject: string, text: string): Promise<void> {
  const t = getTransporter();
  if (!t) {
    throw new Error("SMTP is not configured (set SMTP_HOST in .env)");
  }
  await t.sendMail({
    from: config.smtp.from || config.smtp.user || "porttorch@localhost",
    to,
    subject,
    text,
  });
}
