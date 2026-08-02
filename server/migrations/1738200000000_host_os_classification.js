/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN os_name text,
      ADD COLUMN os_family text,
      ADD COLUMN os_vendor text,
      ADD COLUMN device_type text,
      ADD COLUMN os_accuracy integer;

    CREATE INDEX hosts_os_family_idx ON hosts (os_family);
    CREATE INDEX hosts_device_type_idx ON hosts (device_type);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP INDEX IF EXISTS hosts_device_type_idx;
    DROP INDEX IF EXISTS hosts_os_family_idx;

    ALTER TABLE hosts
      DROP COLUMN IF EXISTS os_name,
      DROP COLUMN IF EXISTS os_family,
      DROP COLUMN IF EXISTS os_vendor,
      DROP COLUMN IF EXISTS device_type,
      DROP COLUMN IF EXISTS os_accuracy;
  `);
};
