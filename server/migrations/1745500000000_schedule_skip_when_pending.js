exports.up = (pgm) => {
  pgm.sql(`
    -- Which schedule produced this request. Until now a scheduled request
    -- carried only requested_by = 'schedule', so nothing could answer
    -- "does this schedule already have a run waiting?" - and the scheduler
    -- therefore queued another one every time it came due, however many
    -- were already stacked up. A scanner that stops polling turns an
    -- hourly schedule into 24 queued requests a day, all of which then run
    -- back-to-back when it returns.
    --
    -- ON DELETE SET NULL rather than CASCADE, matching how scan_requests
    -- already treats a deleted scanner agent and a deleted host: a request
    -- that has already run is history, and deleting the schedule that
    -- caused it must not erase that.
    ALTER TABLE scan_requests
      ADD COLUMN schedule_id uuid REFERENCES scan_schedules(id) ON DELETE SET NULL;

    -- Partial index: the scheduler's own "is anything still pending for
    -- this schedule" check, which is the only query that uses this column
    -- and only ever looks at pending rows.
    CREATE INDEX scan_requests_schedule_pending_idx
      ON scan_requests (schedule_id)
      WHERE status = 'pending';

    -- A skipped run is not a failure and not an error, but it is
    -- something an operator should be able to see - otherwise "this
    -- schedule has produced nothing for two days" looks identical to
    -- "this schedule is fine". Counted rather than logged per occurrence
    -- so the dashboard can show it without anyone reading logs.
    ALTER TABLE scan_schedules
      ADD COLUMN skipped_runs integer NOT NULL DEFAULT 0,
      ADD COLUMN last_skipped_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP INDEX scan_requests_schedule_pending_idx;
    ALTER TABLE scan_requests DROP COLUMN schedule_id;
    ALTER TABLE scan_schedules DROP COLUMN skipped_runs, DROP COLUMN last_skipped_at;
  `);
};
