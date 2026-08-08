/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE epss_cache
      ADD COLUMN alert_sent_at timestamptz;

    -- Singleton row (id always 1) tracking when the daily digest email last
    -- fired, so a webserver restart can't cause a duplicate send within the
    -- same UTC day - same "persist last-fired state" reasoning as
    -- tls_certificates.expiry_alert_sent_at / scan_schedules.last_run_at.
    CREATE TABLE digest_email_state (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      last_sent_date date
    );
    INSERT INTO digest_email_state (id, last_sent_date) VALUES (1, NULL);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS digest_email_state;
    ALTER TABLE epss_cache
      DROP COLUMN IF EXISTS alert_sent_at;
  `);
};
