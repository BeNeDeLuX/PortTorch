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
};
