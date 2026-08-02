/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN mac_address text,
      ADD COLUMN mac_vendor text;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      DROP COLUMN mac_address,
      DROP COLUMN mac_vendor;
  `);
};
