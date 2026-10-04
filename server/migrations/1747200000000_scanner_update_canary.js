/* eslint-disable */
exports.shorthands = undefined;

// Staggered auto-updates (scannerUpdate/autoUpdate.ts).
//
// scanner_agents.update_canary: a scanner that takes a new release first.
// While any live scanner is marked, the others are only auto-updated once
// a canary has completed a scan on that release - so a broken release
// stops at one scanner instead of reaching the whole fleet at once.
//
// scanner_agents.version_changed_at: when this scanner started reporting
// the version it reports now, which is what "a scan on the new release"
// is measured from. Set to now() for every scanner that already reports a
// version: the moment it actually changed is not recorded anywhere, and
// guessing an earlier one could let a scan from before the update count
// as proof the update works.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      ADD COLUMN update_canary boolean NOT NULL DEFAULT false,
      ADD COLUMN version_changed_at timestamptz;
    UPDATE scanner_agents SET version_changed_at = now() WHERE version IS NOT NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      DROP COLUMN version_changed_at,
      DROP COLUMN update_canary;
  `);
};
