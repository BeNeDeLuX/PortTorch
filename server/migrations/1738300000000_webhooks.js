/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE webhooks (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      url text NOT NULL,
      enabled boolean NOT NULL DEFAULT true,
      events text[] NOT NULL DEFAULT '{}',
      created_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE tls_certificates
      ADD COLUMN expiry_alert_sent_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE tls_certificates
      DROP COLUMN IF EXISTS expiry_alert_sent_at;

    DROP TABLE IF EXISTS webhooks;
  `);
};
