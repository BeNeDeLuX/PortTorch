/* eslint-disable */
exports.shorthands = undefined;

// SMTP moves out of config.ts (SMTP_HOST/PORT/SECURE/USER/PASSWORD/FROM)
// and into app_settings, alongside host_retention_days and the rest, for
// the same reason those moved: an admin needs to fix a mail server, a
// changed password, or a wrong sender address from the Settings page,
// not by editing .env and redeploying. Mail config is also the setting
// most likely to be wrong on first setup and to need a couple of quick
// iterations to get right, which is exactly the loop a redeploy ruins.
//
// Seeded once from whatever the env vars currently hold, so an existing
// deployment's working configuration carries over rather than silently
// going blank on upgrade - the same one-time-seed idiom
// 1742600000000_app_settings_host_retention.js uses. This is the last
// time those variables are read; webhooks/email.ts reads exclusively
// from these columns from here on.
//
// smtp_password is stored in plaintext, necessarily: SMTP AUTH needs the
// credential itself, so unlike an API key or a user password there is
// nothing to hash it into. It is never returned by the API (GET
// /api/settings/app reports only whether one is set).
// Both statements go through pgm.db.query rather than pgm.sql, and in
// that order deliberately: pgm.sql only *queues* SQL to run after up()
// returns, so an awaited pgm.db.query mixed with it would execute first -
// against columns that don't exist yet.
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE app_settings
      ADD COLUMN smtp_host text,
      ADD COLUMN smtp_port integer NOT NULL DEFAULT 587,
      ADD COLUMN smtp_secure boolean NOT NULL DEFAULT false,
      ADD COLUMN smtp_user text,
      ADD COLUMN smtp_password text,
      ADD COLUMN smtp_from text
  `);

  // Parameterized rather than interpolated: a password legitimately
  // contains quotes and backslashes, and building this as a SQL string
  // would break the migration (or worse) on exactly those.
  const port = parseInt(process.env.SMTP_PORT ?? "587", 10);
  await pgm.db.query(
    `UPDATE app_settings
        SET smtp_host = $1,
            smtp_port = $2,
            smtp_secure = $3,
            smtp_user = $4,
            smtp_password = $5,
            smtp_from = $6
      WHERE id = 1`,
    [
      process.env.SMTP_HOST || null,
      Number.isFinite(port) && port > 0 ? port : 587,
      process.env.SMTP_SECURE === "true",
      process.env.SMTP_USER || null,
      process.env.SMTP_PASSWORD || null,
      process.env.SMTP_FROM || null,
    ]
  );
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN IF EXISTS smtp_host,
      DROP COLUMN IF EXISTS smtp_port,
      DROP COLUMN IF EXISTS smtp_secure,
      DROP COLUMN IF EXISTS smtp_user,
      DROP COLUMN IF EXISTS smtp_password,
      DROP COLUMN IF EXISTS smtp_from;
  `);
};
