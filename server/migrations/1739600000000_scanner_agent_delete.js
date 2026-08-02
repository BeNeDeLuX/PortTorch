/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Deleting a scanner agent must not silently erase real scan history -
    -- scan_jobs (and everything cascading from it: host_port_observations,
    -- screenshots, tls_certificates, etc.) and scan_requests are preserved
    -- with scanner_agent_id set to NULL, the same pattern already used for
    -- scan_requests.host_id when a host is deleted. scan_schedules and
    -- scan_excludes are left cascading (unchanged) - a schedule or an
    -- agent-scoped exclude has no meaning once its agent is gone, unlike
    -- read-only historical scan data.
    ALTER TABLE scan_jobs ALTER COLUMN scanner_agent_id DROP NOT NULL;
    ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_scanner_agent_id_fkey;
    ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_scanner_agent_id_fkey
      FOREIGN KEY (scanner_agent_id) REFERENCES scanner_agents(id) ON DELETE SET NULL;

    ALTER TABLE scan_requests ALTER COLUMN scanner_agent_id DROP NOT NULL;
    ALTER TABLE scan_requests DROP CONSTRAINT scan_requests_scanner_agent_id_fkey;
    ALTER TABLE scan_requests ADD CONSTRAINT scan_requests_scanner_agent_id_fkey
      FOREIGN KEY (scanner_agent_id) REFERENCES scanner_agents(id) ON DELETE SET NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_requests DROP CONSTRAINT scan_requests_scanner_agent_id_fkey;
    ALTER TABLE scan_requests ADD CONSTRAINT scan_requests_scanner_agent_id_fkey
      FOREIGN KEY (scanner_agent_id) REFERENCES scanner_agents(id) ON DELETE CASCADE;
    DELETE FROM scan_requests WHERE scanner_agent_id IS NULL;
    ALTER TABLE scan_requests ALTER COLUMN scanner_agent_id SET NOT NULL;

    ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_scanner_agent_id_fkey;
    ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_scanner_agent_id_fkey
      FOREIGN KEY (scanner_agent_id) REFERENCES scanner_agents(id) ON DELETE CASCADE;
    DELETE FROM scan_jobs WHERE scanner_agent_id IS NULL;
    ALTER TABLE scan_jobs ALTER COLUMN scanner_agent_id SET NOT NULL;
  `);
};
