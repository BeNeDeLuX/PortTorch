/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // Was config.ts's hostRetentionDays (HOST_RETENTION_DAYS env var,
  // default 180) - moved into app_settings alongside require_admin_totp
  // so an admin can change it live from the Settings page instead of
  // needing a redeploy, same reasoning as that column. Seeded from
  // whatever HOST_RETENTION_DAYS is currently set to (falling back to
  // the same 180 default config.ts itself used) so an existing
  // deployment's customized value carries over rather than silently
  // reverting to 180 on upgrade - this is the one and only time the env
  // var is read; retention.ts reads exclusively from this column from
  // here on.
  const envDays = parseInt(process.env.HOST_RETENTION_DAYS ?? "180", 10);
  const defaultDays = Number.isFinite(envDays) && envDays >= 0 ? envDays : 180;
  pgm.sql(`
    ALTER TABLE app_settings ADD COLUMN host_retention_days integer NOT NULL DEFAULT ${defaultDays};
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings DROP COLUMN IF EXISTS host_retention_days;
  `);
};
