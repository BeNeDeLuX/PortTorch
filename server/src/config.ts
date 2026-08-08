function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  port: parseInt(process.env.PORT ?? "8443", 10),
  databaseUrl: required("DATABASE_URL"),
  sessionSecret: required("SESSION_SECRET"),
  certDir: process.env.CERT_DIR ?? "/data/certs",
  screenshotDir: process.env.SCREENSHOT_DIR ?? "/data/screenshots",
  isProduction: process.env.NODE_ENV === "production",
  // Hosts not seen in this many days are purged (see src/retention.ts).
  // 0 disables the sweep entirely.
  hostRetentionDays: parseInt(process.env.HOST_RETENTION_DAYS ?? "180", 10),
  // A scan_job stuck in "running" or a scan_request stuck in "pending"/
  // "claimed" for longer than this is flagged stale in the dashboard
  // (see src/lib/staleness.ts) - typically means the scanner that owns it
  // is offline or died mid-scan. Purely a UI hint, nothing is deleted or
  // reassigned automatically.
  staleScanThresholdMinutes: parseInt(process.env.STALE_SCAN_THRESHOLD_MINUTES ?? "60", 10),
  // Optional: raises the NVD API rate limit from 5 to 50 requests/30s
  // (see src/cve/sync.ts). Works fine without one, just slower to sync
  // many distinct CPEs.
  nvdApiKey: process.env.NVD_API_KEY,
  // Optional - only needed if an admin actually creates an "email" alert
  // channel (see src/webhooks/email.ts). Deliberately not required() like
  // databaseUrl/sessionSecret: a deployment that only ever uses webhook
  // channels (the pre-existing default) shouldn't be forced to configure
  // SMTP it'll never use.
  smtp: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT ?? "587", 10),
    // STARTTLS (the common case on port 587) is negotiated after connect
    // regardless of this flag; `secure: true` is only for implicit-TLS
    // ports like 465 - matches nodemailer's own documented behavior.
    secure: process.env.SMTP_SECURE === "true",
    user: process.env.SMTP_USER,
    password: process.env.SMTP_PASSWORD,
    from: process.env.SMTP_FROM,
  },
  // A CVE's EPSS score (see src/cve/epssSync.ts) at or above this fires a
  // "vulnerability.high_epss" webhook once. 0.5 = 50% predicted exploit
  // probability in the next 30 days - FIRST.org's own docs note the
  // overall dataset's mean is well under 1%, so 50% is already a strong
  // signal, not a low bar that'd fire constantly.
  epssAlertThreshold: parseFloat(process.env.EPSS_ALERT_THRESHOLD ?? "0.5"),
  // UTC hour (0-23) the daily digest email fires at, if any webhook/email
  // channel is subscribed to "digest.daily" - see src/digest/emailDigest.ts.
  digestEmailHourUtc: parseInt(process.env.DIGEST_EMAIL_HOUR_UTC ?? "8", 10),
};
