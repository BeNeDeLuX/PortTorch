/* eslint-disable */
exports.shorthands = undefined;

// A scan that stopped early - cancelled, or failed partway - can be
// resumed with only what it never finished. The scanner works out that
// remainder itself (it is the only side that knows which discovery blocks
// masscan completed and which hosts made it all the way through) and
// reports it on the completion PATCH; see pipeline.ScanCoverage.
//
// remaining_target_spec is NULL for a scan that finished, for one from a
// scanner too old to report it, and for one that stopped before covering
// anything - in each case there is nothing to offer as a resume.
//
// resumed_at / resumed_scan_request_id make resuming a one-time action: a
// second click must not queue the same remainder twice. SET NULL rather
// than CASCADE, matching how scan_requests' own links to jobs and hosts
// already behave - the job is history and outlives the request it spawned.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_jobs ADD COLUMN remaining_target_spec text;
    ALTER TABLE scan_jobs ADD COLUMN resumed_at timestamptz;
    ALTER TABLE scan_jobs ADD COLUMN resumed_scan_request_id uuid REFERENCES scan_requests(id) ON DELETE SET NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_jobs DROP COLUMN IF EXISTS resumed_scan_request_id;
    ALTER TABLE scan_jobs DROP COLUMN IF EXISTS resumed_at;
    ALTER TABLE scan_jobs DROP COLUMN IF EXISTS remaining_target_spec;
  `);
};
