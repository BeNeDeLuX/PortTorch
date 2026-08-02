/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      ADD COLUMN totp_secret text,
      ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN totp_recovery_codes text[];
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP COLUMN IF EXISTS totp_secret,
      DROP COLUMN IF EXISTS totp_enabled,
      DROP COLUMN IF EXISTS totp_recovery_codes;
  `);
};
