/* eslint-disable */
exports.shorthands = undefined;

// Live-ish progress for a running scan (current stage + a capped rolling
// buffer of recent log lines) - separate from scan_jobs itself since this
// gets updated far more often (every few seconds while a scan runs) than
// anything else on that row, and there's nothing here worth keeping once
// the job finishes (unlike scan_jobs' own history, which is append-only
// and permanent by design). ON DELETE CASCADE with scan_jobs mirrors that:
// this is disposable working state, not part of the audit trail.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_job_progress (
      scan_job_id uuid PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
      current_stage text,
      stage_detail text,
      recent_logs jsonb NOT NULL DEFAULT '[]'::jsonb,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS scan_job_progress;
  `);
};
