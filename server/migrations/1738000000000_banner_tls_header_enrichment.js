/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE host_port_observations
      ADD COLUMN extra_info text,
      ADD COLUMN os_type text,
      ADD COLUMN cpes text[];

    ALTER TABLE tls_certificates
      ADD COLUMN tls_version text,
      ADD COLUMN cipher_suite text,
      ADD COLUMN key_algorithm text,
      ADD COLUMN key_bits integer;

    ALTER TABLE screenshots
      ADD COLUMN headers jsonb;

    -- current_host_ports is "SELECT * FROM host_port_observations", but a
    -- view's "*" is expanded to a fixed column list at creation time - it
    -- does not pick up newly added columns on its own, so it must be
    -- recreated for extra_info/os_type/cpes to show up through it.
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

    ALTER TABLE screenshots
      DROP COLUMN IF EXISTS headers;

    ALTER TABLE tls_certificates
      DROP COLUMN IF EXISTS tls_version,
      DROP COLUMN IF EXISTS cipher_suite,
      DROP COLUMN IF EXISTS key_algorithm,
      DROP COLUMN IF EXISTS key_bits;

    ALTER TABLE host_port_observations
      DROP COLUMN IF EXISTS extra_info,
      DROP COLUMN IF EXISTS os_type,
      DROP COLUMN IF EXISTS cpes;

    CREATE VIEW current_host_ports AS
      SELECT DISTINCT ON (host_id, port, protocol) *
      FROM host_port_observations
      ORDER BY host_id, port, protocol, observed_at DESC;
  `);
};
