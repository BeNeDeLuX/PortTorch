/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // Fleet Health's "Scan Queue" card (useFleetHealth.ts) used to warn the
  // moment even one scan_requests row was pending - a real report of this
  // being too sensitive in normal operation (a handful of queued requests
  // during a busy period is often fine). Default 1 preserves today's
  // exact behavior for anyone who doesn't change it; an admin can raise
  // it from the Settings page. Independent of the existing time-based
  // "critical" escalation (STALE_QUEUE_THRESHOLD_MS in useFleetHealth.ts)
  // - a single request stuck for 30+ minutes still escalates straight to
  // critical regardless of this threshold, since that specifically means
  // a scanner has stopped polling, not just "the queue is a bit busy."
  pgm.sql(`
    ALTER TABLE app_settings ADD COLUMN scan_queue_warning_threshold integer NOT NULL DEFAULT 1;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings DROP COLUMN IF EXISTS scan_queue_warning_threshold;
  `);
};
