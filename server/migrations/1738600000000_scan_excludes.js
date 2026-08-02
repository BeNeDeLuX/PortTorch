/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_excludes (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      kind text NOT NULL CHECK (kind IN ('ip', 'port')),
      value text NOT NULL,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (kind, value)
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS scan_excludes;
  `);
};
