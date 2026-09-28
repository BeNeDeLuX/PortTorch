/* eslint-disable */
exports.shorthands = undefined;

// Tags an ad-hoc scan or a schedule can carry alongside its target - so
// "give me exactly the assets this scan found" has an answer that isn't
// re-reading the scan's own target spec after the fact. Applied to every
// host that scan (or, for a schedule, every run of it) actually touches,
// via the same host_tags table manual tags and the service-derived
// auto-tags already share - see ingest/routes.ts's ingestHostPayload.
//
// A plain text[], not a profile-style snapshot with its own resolve
// module: unlike nse_profile/nuclei_profile there is no admin-curated
// named list behind it, just the literal tag names typed into the form,
// so there is nothing to resolve and nothing that can drift.
//
// Nullable with no default, matching every other optional per-request
// column here (masscan_rate, priority's own snapshot precedent) - NULL
// means "no tags requested", which is what every existing row already
// means and keeps meaning.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_requests ADD COLUMN tags text[];
    ALTER TABLE scan_schedules ADD COLUMN tags text[];
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_requests DROP COLUMN IF EXISTS tags;
    ALTER TABLE scan_schedules DROP COLUMN IF EXISTS tags;
  `);
};
