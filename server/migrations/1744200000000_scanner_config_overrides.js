/* eslint-disable */
exports.shorthands = undefined;

/**
 * Dashboard-managed scanner tuning.
 *
 * masscanRate could already be overridden per scan, but a scanner's own
 * baseline - concurrency, retries, screenshot/nuclei timeouts - lived
 * only in config.yaml on the scanner host, so changing it meant SSH,
 * an editor and a service restart. That's out of step with everything
 * else about this scanner by now: it can already update its own binary
 * and refresh its nuclei templates from the dashboard.
 *
 * Deliberately a jsonb bag rather than a column per setting: it holds
 * only allowlisted keys (src/scannerConfig/tunables.ts validates on the
 * way in, and the scanner ignores anything it doesn't know), and adding
 * the next tunable shouldn't need a migration on both sides. NULL or an
 * empty object means "this scanner uses its config.yaml exactly as
 * written", which is what every existing agent has.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scanner_agents ADD COLUMN config_overrides jsonb`);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scanner_agents DROP COLUMN IF EXISTS config_overrides`);
};
