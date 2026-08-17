/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // Was config.ts's staleScanThresholdMinutes (STALE_SCAN_THRESHOLD_MINUTES
  // env var, default 60) - moved into app_settings alongside
  // host_retention_days/require_admin_totp so an admin can change it live
  // from the Settings page instead of needing a redeploy, same reasoning
  // as those columns. Seeded from whatever STALE_SCAN_THRESHOLD_MINUTES is
  // currently set to (falling back to the same 60 default config.ts
  // itself used) so an existing deployment's customized value carries
  // over rather than silently reverting to 60 on upgrade - this is the
  // one and only time the env var is read; lib/staleness.ts's callers
  // read exclusively from this column from here on.
  const envMinutes = parseInt(process.env.STALE_SCAN_THRESHOLD_MINUTES ?? "60", 10);
  const defaultMinutes = Number.isFinite(envMinutes) && envMinutes > 0 ? envMinutes : 60;
  pgm.sql(`
    ALTER TABLE app_settings ADD COLUMN stale_scan_threshold_minutes integer NOT NULL DEFAULT ${defaultMinutes};
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings DROP COLUMN IF EXISTS stale_scan_threshold_minutes;
  `);
};
