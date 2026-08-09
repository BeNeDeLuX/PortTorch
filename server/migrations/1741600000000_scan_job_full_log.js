/* eslint-disable */
exports.shorthands = undefined;

// The complete progress log for a finished scan, uploaded once by the
// scanner at Close() (see scanner/internal/progress/tracker.go) - unlike
// scan_job_progress.recent_logs (a capped rolling buffer overwritten
// every few seconds while the scan runs, and never more than the
// scanner's maxLogLines), this holds every line up to the scanner's own,
// much higher maxFullLogLines ceiling. Separate table from scan_jobs
// itself and from scan_job_progress, since it's written exactly once per
// job rather than either permanently (scan_jobs) or every few seconds
// (scan_job_progress) - a plain PRIMARY KEY + ON CONFLICT upsert is
// still used rather than a bare INSERT, purely as a safeguard against a
// retried push, not because more than one push is expected in practice.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_job_full_log (
      scan_job_id uuid PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
      logs jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS scan_job_full_log;
  `);
};
