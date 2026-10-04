/* eslint-disable */
exports.shorthands = undefined;

// Address patterns (lib/targetPattern.ts).
//
// scan_requests.target_pattern: the pattern a request's target was
// expanded from, when it was ("10.46.*.125"). target_spec keeps holding
// the expanded list, because that is what the scanner runs; the pattern is
// kept beside it so Scan History can show what was asked for and Rescan
// can reuse it, rather than either one only ever seeing a list of 256
// addresses. NULL for a target typed without pattern syntax.
//
// scan_excludes.kind gains 'ip_pattern': a range plus a pattern, stored as
// one value ("10.46.0.0/16 *.2") so the existing (kind, value) uniqueness
// covers it - the same pattern in two ranges is two rules. Expanded into
// concrete entries whenever a scanner fetches its excludes, so scanners
// need no change to honour it.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_requests ADD COLUMN target_pattern text;

    ALTER TABLE scan_excludes
      DROP CONSTRAINT scan_excludes_kind_check,
      ADD CONSTRAINT scan_excludes_kind_check CHECK (kind IN ('ip', 'port', 'ip_port', 'ip_pattern'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM scan_excludes WHERE kind = 'ip_pattern';
    ALTER TABLE scan_excludes
      DROP CONSTRAINT scan_excludes_kind_check,
      ADD CONSTRAINT scan_excludes_kind_check CHECK (kind IN ('ip', 'port', 'ip_port'));
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS target_pattern;
  `);
};
