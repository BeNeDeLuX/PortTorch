/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      ADD COLUMN pref_timezone text,
      ADD COLUMN pref_time_format text CHECK (pref_time_format IN ('h12', 'h24'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP COLUMN IF EXISTS pref_timezone,
      DROP COLUMN IF EXISTS pref_time_format;
  `);
};
