/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_jobs
      ADD COLUMN cancellable boolean NOT NULL DEFAULT false,
      ADD COLUMN cancel_requested_at timestamptz;

    ALTER TABLE scan_requests
      DROP CONSTRAINT scan_requests_status_check,
      ADD CONSTRAINT scan_requests_status_check
        CHECK (status IN ('pending', 'claimed', 'completed', 'failed', 'cancelled'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    UPDATE scan_requests SET status = 'failed' WHERE status = 'cancelled';
    ALTER TABLE scan_requests
      DROP CONSTRAINT scan_requests_status_check,
      ADD CONSTRAINT scan_requests_status_check
        CHECK (status IN ('pending', 'claimed', 'completed', 'failed'));

    ALTER TABLE scan_jobs
      DROP COLUMN cancellable,
      DROP COLUMN cancel_requested_at;
  `);
};
