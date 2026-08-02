/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_excludes
      DROP CONSTRAINT scan_excludes_kind_check,
      ADD CONSTRAINT scan_excludes_kind_check CHECK (kind IN ('ip', 'port', 'ip_port'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM scan_excludes WHERE kind = 'ip_port';

    ALTER TABLE scan_excludes
      DROP CONSTRAINT scan_excludes_kind_check,
      ADD CONSTRAINT scan_excludes_kind_check CHECK (kind IN ('ip', 'port'));
  `);
};
