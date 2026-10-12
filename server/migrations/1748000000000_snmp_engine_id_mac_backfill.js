/* eslint-disable */
exports.shorthands = undefined;

// Scanner 0.30.1 derives a MAC from the SNMPv3 engine ID that snmp-info
// already reads (engineIDFormat: mac). The output itself has been stored in
// host_port_observations.nse_extra all along, so hosts scanned before that
// release are filled in once, here, instead of waiting for a rescan.
//
// The same rule the scanner applies: only a host with neither an
// ARP-resolved MAC nor a derived one from a stronger source, only the
// "mac" format, never an all-zero address, and from that host's newest
// observation carrying one.
exports.up = (pgm) => {
  pgm.sql(`
    WITH engine AS (
      SELECT DISTINCT ON (o.host_id)
             o.host_id,
             upper(substring(e->>'output' from 'engineIDData:\\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')) AS mac
      FROM host_port_observations o
      CROSS JOIN LATERAL jsonb_array_elements(o.nse_extra) e
      WHERE e->>'id' = 'snmp-info'
        AND e->>'output' ~* 'engineIDFormat:\\s*mac\\s*(\\n|$)'
      ORDER BY o.host_id, o.observed_at DESC
    )
    UPDATE hosts h
    SET derived_mac_address = engine.mac,
        derived_mac_source = 'snmp-engine-id'
    FROM engine
    WHERE h.id = engine.host_id
      AND engine.mac IS NOT NULL
      AND engine.mac <> '00:00:00:00:00:00'
      AND h.mac_address IS NULL
      AND h.derived_mac_address IS NULL
  `);
};

// Nothing to undo: the values are what a rescan with 0.30.1 would write.
exports.down = () => {};
