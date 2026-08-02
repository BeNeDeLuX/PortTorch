/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts ADD COLUMN scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE SET NULL;

    -- Backfill from each host's most recently observed scan job, i.e.
    -- whichever scanner most recently reported it - this can't collide
    -- with itself: ip was globally unique before this migration, so
    -- there's still at most one row per ip at this point, and assigning
    -- it a scanner_agent_id can't create a new duplicate.
    UPDATE hosts h
    SET scanner_agent_id = latest.scanner_agent_id
    FROM (
      SELECT DISTINCT ON (hpo.host_id)
        hpo.host_id,
        sj.scanner_agent_id
      FROM host_port_observations hpo
      JOIN scan_jobs sj ON sj.id = hpo.scan_job_id
      ORDER BY hpo.host_id, hpo.observed_at DESC
    ) latest
    WHERE h.id = latest.host_id;

    ALTER TABLE hosts DROP CONSTRAINT hosts_ip_key;
    ALTER TABLE hosts ADD CONSTRAINT hosts_ip_scanner_agent_id_key UNIQUE (ip, scanner_agent_id);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts DROP CONSTRAINT hosts_ip_scanner_agent_id_key;
    -- This fails if two different scanner agents' hosts now genuinely
    -- share an ip - which is exactly what this migration exists to allow.
    -- Rolling back after that's actually happened isn't a safe automatic
    -- operation; resolve the duplicates by hand first if you really need to.
    ALTER TABLE hosts ADD CONSTRAINT hosts_ip_key UNIQUE (ip);
    ALTER TABLE hosts DROP COLUMN scanner_agent_id;
  `);
};
