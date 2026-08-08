/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE epss_cache (
      cve_id text PRIMARY KEY,
      epss real NOT NULL,
      percentile real NOT NULL,
      checked_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS epss_cache;
  `);
};
