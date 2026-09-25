/* eslint-disable */
exports.shorthands = undefined;

// A Windows host with no PTR record has no name in the dashboard at all,
// even though it announces one over RDP and SMB; and a MAC is only ever
// resolved by ARP, so a host one routed hop away never has one - even
// though Windows hands its own out over NetBIOS, which crosses routers.
//
// These hold what the scan could work out for itself, and they are
// deliberately *separate columns* rather than a fallback written into
// hostname/mac_address. Three reasons:
//
//   - hostname is rewritten from nmap's PTR lookup on every scan,
//     including to null when the lookup finds nothing. Anything derived
//     written there would be erased by the next scan.
//   - The two can disagree, and that is worth seeing rather than
//     resolving. Measured on a real fleet: a host whose PTR said
//     "filer01.example.internal" reported itself over SMB as "FILER02".
//     Which is wrong is not something a scanner can decide.
//   - "This name is in DNS" and "this machine claims this name" are
//     different kinds of fact. The *_source columns keep that visible;
//     a consumer that cannot tell them apart treats the weaker as the
//     stronger.
//
// Nothing here is ever overwritten by a scan that finds no evidence - the
// ingest upsert coalesces, the same way os_family and mac_address already
// do for their own root-only/ARP-only reasons.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN derived_hostname text,
      ADD COLUMN derived_hostname_source text,
      ADD COLUMN derived_mac_address text,
      ADD COLUMN derived_mac_vendor text,
      ADD COLUMN derived_mac_source text
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      DROP COLUMN derived_hostname,
      DROP COLUMN derived_hostname_source,
      DROP COLUMN derived_mac_address,
      DROP COLUMN derived_mac_vendor,
      DROP COLUMN derived_mac_source
  `);
};
