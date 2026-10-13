/* eslint-disable */
exports.shorthands = undefined;

// MAC address prefixes and their manufacturers, so a MAC can be named
// even when nmap did not resolve a vendor - which it never does for the
// MACs the scanner derives from SNMP or NetBIOS (see scanner/CLAUDE.md),
// the very hosts ARP cannot reach. Synced weekly by src/macOui/sync.ts
// from nmap's own nmap-mac-prefixes, so a name matches what nmap writes
// into hosts.mac_vendor, plus the IEEE registry for prefixes nmap's copy
// does not have yet.
//
// The prefix is upper-case hex without separators: 6 digits for a 24-bit
// MA-L block, 7 or 9 for the finer MA-M/MA-S blocks; a lookup takes the
// longest match.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE mac_oui (
      prefix text PRIMARY KEY CHECK (prefix ~ '^[0-9A-F]{6}([0-9A-F]|[0-9A-F]{3})?$'),
      vendor text NOT NULL
    );

    CREATE TABLE mac_oui_state (
      id integer PRIMARY KEY CHECK (id = 1),
      synced_at timestamptz,
      entries integer,
      last_attempt_at timestamptz,
      last_error text
    );
    INSERT INTO mac_oui_state (id) VALUES (1);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`DROP TABLE mac_oui_state; DROP TABLE mac_oui;`);
};
