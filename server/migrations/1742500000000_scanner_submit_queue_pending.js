/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Reported by the scanner on every ingest request (the
    -- X-Scanner-Submit-Queue-Pending header, alongside the pre-existing
    -- X-Scanner-Version one - see client.go's setAuthHeaders) - the
    -- current size of that scanner's local internal/submitqueue retry
    -- backlog (host submissions that failed and are waiting to be
    -- resubmitted). Null until a scanner build with this support has made
    -- at least one request, same "absence means unknown, not zero"
    -- treatment as the version column right above it - a scanner that's
    -- never reported can't be assumed to have an empty queue.
    ALTER TABLE scanner_agents ADD COLUMN submit_queue_pending integer;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents DROP COLUMN IF EXISTS submit_queue_pending;
  `);
};
