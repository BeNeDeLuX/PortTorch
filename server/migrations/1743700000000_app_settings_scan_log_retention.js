/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- How long a finished scan's pushed log output is kept
    -- (scan_job_full_log, scan_job_progress). 0 disables the purge.
    --
    -- These were the only tables in the schema with no bound at all:
    -- retention only ever deleted hosts and audit_log, and nothing has
    -- ever deleted a scan_jobs row, so the log tables hanging off it were
    -- never reached either. Measured against real jsonb, a 500-line log
    -- is ~63 kB and the 10000-line cap ~1250 kB, so an hourly schedule
    -- accumulates roughly 0.5-10 GB per year with no upper limit.
    --
    -- Its own setting rather than reusing host_retention_days (the way
    -- audit_log does) because the two age at genuinely different rates:
    -- host records are the product, scan logs are diagnostics that stop
    -- being interesting within days. 30 is short enough to bound growth
    -- and long enough to still investigate last month's odd scan.
    ALTER TABLE app_settings
      ADD COLUMN scan_log_retention_days integer NOT NULL DEFAULT 30;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`ALTER TABLE app_settings DROP COLUMN IF EXISTS scan_log_retention_days;`);
};
