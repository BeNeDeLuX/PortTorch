/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE cve_cache (
      cpe text PRIMARY KEY,
      cves jsonb NOT NULL,
      checked_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS cve_cache;
  `);
};
