/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE host_port_observations
      ADD COLUMN ftp_anon_listing text,
      ADD COLUMN smb_shares text;

    -- current_host_ports is "SELECT * FROM host_port_observations", and
    -- Postgres freezes a view's * into a fixed column list at creation
    -- time - has to be dropped and recreated whenever the underlying
    -- table gains a column that should show up through the view (see
    -- CLAUDE.md's "Database shape" section, and the earlier
    -- 1738200000000_host_os_classification.js migration that hit this
    -- same thing).
    DROP VIEW current_host_ports;
    CREATE VIEW current_host_ports AS
      SELECT DISTINCT ON (host_id, port, protocol) *
      FROM host_port_observations
      ORDER BY host_id, port, protocol, observed_at DESC;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP VIEW current_host_ports;

    ALTER TABLE host_port_observations
      DROP COLUMN ftp_anon_listing,
      DROP COLUMN smb_shares;

    CREATE VIEW current_host_ports AS
      SELECT DISTINCT ON (host_id, port, protocol) *
      FROM host_port_observations
      ORDER BY host_id, port, protocol, observed_at DESC;
  `);
};
