/* eslint-disable */
exports.shorthands = undefined;

// The exact Windows build, e.g. "10.0.17763", read out of an NTLM message
// the scanner elicited with null credentials - see the scanner's
// windowsversion.go. nmap's own -O fingerprint is far too coarse to
// answer "which version is this": for Windows it reports a family
// spanning several releases at once, which is why os_name is not the
// place for this.
//
// Only the build is stored. What it is *called* and whether it is still
// supported is derived on read (frontend/src/lib/windowsBuilds.ts)
// rather than written here, for two reasons: that table gains entries and
// its support dates pass with time, so deriving it means a new release
// name or a lapsed support date reaches every existing host on the next
// deploy instead of only the hosts scanned afterwards.
//
// windows_build_source names which script produced it, the same way the
// derived hostname and MAC carry theirs - eight nmap scripts can elicit
// an NTLM message, and which one answered is worth knowing.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN windows_build text,
      ADD COLUMN windows_build_source text
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      DROP COLUMN windows_build,
      DROP COLUMN windows_build_source
  `);
};
