/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      ADD COLUMN version text;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      DROP COLUMN IF EXISTS version;
  `);
};
