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
  // GitHub "owner/repo" slug scanner-vX.Y.Z releases are published under
  // (see src/scannerUpdate/githubSync.ts) - overridable for a fork/mirror,
  // defaults to this project's own repo.
  githubRepoSlug: process.env.GITHUB_REPO_SLUG ?? "BeNeDeLuX/PortTorch",
  // A scanner's oldest pending scan_requests row older than this fires a
  // "scan_queue.backlog" webhook (see src/webhooks/operationalAlerts.ts) -
  // a strong signal that scanner has stopped polling entirely, not just
  // that it's mid-scan on something else. Same default as Fleet Health's
  // own client-side display heuristic (frontend/src/pages/FleetHealth.tsx)
  // - independently configurable here since, unlike that page's coloring,
  // this one has a real side effect (an outbound webhook).
  queueBacklogThresholdMinutes: parseInt(process.env.QUEUE_BACKLOG_THRESHOLD_MINUTES ?? "30", 10),
};
