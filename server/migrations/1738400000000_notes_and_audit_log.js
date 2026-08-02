/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN notes text;

    CREATE TABLE audit_log (
      id bigserial PRIMARY KEY,
      event text NOT NULL,
      actor text,
      source_ip inet,
      details jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX audit_log_created_at_idx ON audit_log (created_at DESC);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS audit_log;

    ALTER TABLE hosts
      DROP COLUMN IF EXISTS notes;
  `);
};
