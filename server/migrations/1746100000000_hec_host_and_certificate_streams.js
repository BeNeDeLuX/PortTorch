/* eslint-disable */
exports.shorthands = undefined;

// Two more forwarding streams, closing the half of the SIEM feed that was
// missing: the observation stream carries the port level completely and
// nothing about the host or its certificates, so a Splunk dashboard could
// reproduce the port/service/software charts and none of the OS, device,
// manufacturer, tag or certificate ones.
//
// Different cursors because the tables are different shapes.
// tls_certificates is append-only with a bigserial, so "everything after
// id N" is exact, like observations. hosts is *updated* rather than
// appended - one row per host, refreshed on every scan - so it pages by
// (last_seen_at, id) and a host is re-forwarded whenever a scan touches
// it. That is the right behaviour for an asset feed: the SIEM gets the
// host's current attributes each time they are confirmed, rather than
// once at discovery and never again.
//
// Both default to false, like the two streams before them: turning on a
// stream that would replay the whole fleet is an admin's decision.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hec_state
      ADD COLUMN host_cursor_at timestamptz,
      ADD COLUMN host_cursor_id uuid,
      ADD COLUMN certificate_cursor bigint
  `);
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN hec_hosts_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN hec_certificates_enabled boolean NOT NULL DEFAULT false
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN hec_hosts_enabled,
      DROP COLUMN hec_certificates_enabled
  `);
  pgm.sql(`
    ALTER TABLE hec_state
      DROP COLUMN host_cursor_at,
      DROP COLUMN host_cursor_id,
      DROP COLUMN certificate_cursor
  `);
};
