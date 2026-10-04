/* eslint-disable */
exports.shorthands = undefined;

// Port policies per network (portPolicies/).
//
// A baseline says what a network looked like; a policy says what it may
// look like: "in the DMZ only 22, 80 and 443" (mode 'allow') or "never
// 3389 in the client network" (mode 'deny'). ports uses the scan port
// grammar, U:/T: prefixes included, parsed by lib/portSpec.ts.
//
// Violations are derived on read from current_host_ports, so a policy
// never needs re-evaluating when hosts change. alerted_keys is what the
// last port_policy.violation alert already reported - the same
// come-and-go bookkeeping as network_baselines.
//
// scanner_agent_id follows the scan_excludes convention: NULL covers every
// scanner's hosts in the range. Several policies may cover one network;
// each is evaluated on its own.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE port_policies (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      network cidr NOT NULL,
      scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE CASCADE,
      mode text NOT NULL CHECK (mode IN ('allow', 'deny')),
      ports text NOT NULL,
      note text,
      enabled boolean NOT NULL DEFAULT true,
      alerted_keys text[] NOT NULL DEFAULT '{}',
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`DROP TABLE port_policies;`);
};
