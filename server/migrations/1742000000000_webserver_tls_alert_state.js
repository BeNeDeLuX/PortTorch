/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Singleton row (id always 1) tracking the last-alerted state of the
    -- webserver's OWN TLS listener certificate (settings/certExpiryAlert.ts)
    -- - a filesystem artifact (certDir/cert.pem), not a database row like
    -- tls_certificates (which is scanned *hosts'* certs and dedups its
    -- own alert via a per-row expiry_alert_sent_at column instead). Keyed
    -- by fingerprint rather than just a timestamp so uploading a new
    -- certificate (Settings page) naturally resets alerting - a
    -- different fingerprint has never been alerted for, regardless of
    -- what was alerted before.
    CREATE TABLE webserver_tls_alert_state (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      fingerprint text,
      alert_sent_at timestamptz
    );
    INSERT INTO webserver_tls_alert_state (id, fingerprint, alert_sent_at) VALUES (1, NULL, NULL);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS webserver_tls_alert_state;
  `);
};
