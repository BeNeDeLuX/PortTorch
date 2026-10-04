/* eslint-disable */
exports.shorthands = undefined;

// Approved state per network (baselines/).
//
// A baseline is a moment, not a copy: "this network looked right at
// approved_at". Deviations are whatever changed since, computed on read by
// the same reconstruction the Subnets Changes view uses, so the two can
// never disagree about what changed. Re-approving moves the moment
// forward, which is how a deviation is accepted.
//
// scanner_agent_id follows the scan_excludes / monitored_networks
// convention: NULL covers every scanner's hosts in the range, a value
// scopes it to one - private ranges repeat across sites. Two partial
// unique indexes, since a plain UNIQUE treats every NULL as distinct.
//
// alerted_keys is what the last baseline.deviation alert already said, so
// the check alerts on new deviations only - and forgets a deviation that
// went away, so it alerts again if it comes back.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE network_baselines (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      network cidr NOT NULL,
      scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE CASCADE,
      note text,
      approved_at timestamptz NOT NULL DEFAULT now(),
      approved_by text,
      alerted_keys text[] NOT NULL DEFAULT '{}',
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX network_baselines_global_unique ON network_baselines (network) WHERE scanner_agent_id IS NULL;
    CREATE UNIQUE INDEX network_baselines_scanner_unique ON network_baselines (network, scanner_agent_id) WHERE scanner_agent_id IS NOT NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`DROP TABLE network_baselines;`);
};
