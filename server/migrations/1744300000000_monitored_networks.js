/* eslint-disable */
exports.shorthands = undefined;

/**
 * Network coverage.
 *
 * Everything the platform knows is a *finding*: a host exists because a
 * scan found it. That leaves the inverse question - "which of my ranges
 * haven't been looked at, and since when?" - structurally unanswerable,
 * because a range nobody ever scanned produces no rows anywhere and is
 * indistinguishable from a range with nothing in it.
 *
 * monitored_networks is the declared side of that: the ranges an operator
 * says are theirs, independent of whether anything was ever found in
 * them. Coverage itself is not stored - it's derived on read from
 * scan_jobs.target_spec overlap (see lib/ipRange.ts), so it can never go
 * stale against the scan history the way a cached column would.
 *
 * scanner_agent_id follows scan_excludes exactly: NULL means the range is
 * tracked across every scanner, a non-null value scopes both the coverage
 * calculation and the host count to one scanner - private ranges repeat
 * across unrelated networks, so 10.0.0.0/8 on scanner A and on scanner B
 * are genuinely different things. ON DELETE CASCADE rather than SET NULL:
 * silently promoting a scanner-scoped range to a global one on agent
 * deletion would change what it counts, not just who it belongs to.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    CREATE TABLE monitored_networks (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      label text NOT NULL,
      cidr cidr NOT NULL,
      scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE CASCADE,
      created_by text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    -- Same split as scan_excludes_global_unique/scan_excludes_scanner_unique:
    -- Postgres treats every NULL as distinct in a plain UNIQUE, so a
    -- duplicate global row (scanner_agent_id IS NULL) needs its own
    -- partial index to be caught at all.
    CREATE UNIQUE INDEX monitored_networks_global_unique
      ON monitored_networks (cidr) WHERE scanner_agent_id IS NULL;
    CREATE UNIQUE INDEX monitored_networks_scanner_unique
      ON monitored_networks (cidr, scanner_agent_id) WHERE scanner_agent_id IS NOT NULL;
  `);

  await pgm.db.query(`
    ALTER TABLE app_settings
      ADD COLUMN network_coverage_stale_days integer NOT NULL DEFAULT 30
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE app_settings DROP COLUMN IF EXISTS network_coverage_stale_days`);
  await pgm.db.query(`DROP TABLE IF EXISTS monitored_networks`);
};
