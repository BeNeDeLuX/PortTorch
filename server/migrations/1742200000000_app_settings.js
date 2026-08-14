/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Singleton row (id always 1) for global, admin-configurable toggles
    -- that don't belong to any one user's account - same idiom as
    -- digest_email_state/webserver_tls_alert_state/scanner_release_cache.
    -- Deliberately a DB row rather than a config.ts env var: an admin
    -- needs to be able to flip this from the Settings page at runtime,
    -- without a redeploy.
    CREATE TABLE app_settings (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      -- When true, an admin account without 2FA enabled is redirected to
      -- the Account page (and blocked from everything else) until they
      -- set it up - see auth/routes.ts's totpSetupRequired. Any admin can
      -- flip this back off, same as any other admin-only setting - there
      -- is no separate "super admin" tier in this app.
      require_admin_totp boolean NOT NULL DEFAULT false
    );
    INSERT INTO app_settings (id, require_admin_totp) VALUES (1, false);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS app_settings;
  `);
};
