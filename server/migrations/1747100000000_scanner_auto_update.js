/* eslint-disable */
exports.shorthands = undefined;

// Scanner auto-update (scannerUpdate/autoUpdate.ts).
//
// app_settings.scanner_auto_update: the fleet-wide default, off, so no
// existing deployment starts replacing scanner binaries on its own after
// an upgrade.
//
// scanner_agents.auto_update: a per-scanner override. NULL follows the
// fleet default, true/false pin it either way - the same
// absence-means-inherit convention as scan_excludes.scanner_agent_id.
// A pinned "never" is for a scanner someone deliberately keeps on an older
// build (testing, a host waiting for a maintenance window).
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings ADD COLUMN scanner_auto_update boolean NOT NULL DEFAULT false;
    ALTER TABLE scanner_agents ADD COLUMN auto_update boolean;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents DROP COLUMN auto_update;
    ALTER TABLE app_settings DROP COLUMN scanner_auto_update;
  `);
};
