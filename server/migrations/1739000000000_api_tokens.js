/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE api_tokens (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      token_hash text NOT NULL UNIQUE,
      created_by text,
      last_used_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      revoked_at timestamptz
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS api_tokens;
  `);
};
