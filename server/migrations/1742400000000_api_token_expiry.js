/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Optional expiry, set once at creation time and never editable
    -- afterward (same "immutable once created" treatment as everything
    -- else about a token's identity) - null means "never expires", the
    -- pre-existing behavior for every token created before this column
    -- existed, so this needed no backfill.
    ALTER TABLE api_tokens ADD COLUMN expires_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE api_tokens DROP COLUMN IF EXISTS expires_at;
  `);
};
