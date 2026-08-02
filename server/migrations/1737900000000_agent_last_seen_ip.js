/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      ADD COLUMN last_seen_ip inet;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      DROP COLUMN IF EXISTS last_seen_ip;
  `);
};
