/* eslint-disable */
exports.shorthands = undefined;

// Host counts for the Details popup's progress bar, pushed by the scanner
// with every progress update (see scanner/internal/progress's Counts).
// Structured columns rather than parsed back out of the log lines: a bar
// computed from free-text messages would break the first time one was
// reworded.
//
// All nullable: a scanner older than this sends no counts, and "unknown"
// must not read as "0 of 0 done". Overwritten on every push like the rest
// of scan_job_progress - only the latest snapshot means anything.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_job_progress ADD COLUMN discovery_blocks integer;
    ALTER TABLE scan_job_progress ADD COLUMN discovery_blocks_done integer;
    ALTER TABLE scan_job_progress ADD COLUMN hosts_discovered integer;
    ALTER TABLE scan_job_progress ADD COLUMN hosts_processed integer;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_job_progress DROP COLUMN IF EXISTS hosts_processed;
    ALTER TABLE scan_job_progress DROP COLUMN IF EXISTS hosts_discovered;
    ALTER TABLE scan_job_progress DROP COLUMN IF EXISTS discovery_blocks_done;
    ALTER TABLE scan_job_progress DROP COLUMN IF EXISTS discovery_blocks;
  `);
};
