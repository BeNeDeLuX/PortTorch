/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN probe_hostname text;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      DROP COLUMN probe_hostname;
  `);
};
