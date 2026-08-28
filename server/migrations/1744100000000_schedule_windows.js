/* eslint-disable */
exports.shorthands = undefined;

/**
 * Allowed time windows for scan schedules.
 *
 * A schedule fired whenever its interval or cron said so, with no way to
 * say "not during business hours" - and for an interval schedule there
 * was no way to express it at all, since unlike cron it has no notion of
 * clock time. For a tool that scans production networks that's a real
 * gap: the usual requirement is "sweep the whole /16 nightly, but never
 * while people are working".
 *
 * Stored as minutes since local midnight rather than a `time` column: the
 * only operation is a range comparison, integers make the midnight
 * wrap-around (start > end) explicit, and it avoids node-postgres
 * returning a `time` in a format that varies with the server DateStyle.
 * See src/lib/scanWindow.ts.
 *
 * All-null is "no window", which is what every existing schedule gets -
 * so this changes nothing for anyone who doesn't configure one.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE scan_schedules
      ADD COLUMN window_start_minute smallint
        CHECK (window_start_minute IS NULL OR (window_start_minute >= 0 AND window_start_minute < 1440)),
      ADD COLUMN window_end_minute smallint
        CHECK (window_end_minute IS NULL OR (window_end_minute >= 0 AND window_end_minute < 1440)),
      ADD COLUMN window_days smallint[],
      ADD COLUMN window_timezone text
  `);

  // Half a window is meaningless - "from 22:00" with no end has no
  // defensible reading - so the pair is enforced at the database level
  // rather than only in the route's zod schema.
  await pgm.db.query(`
    ALTER TABLE scan_schedules
      ADD CONSTRAINT scan_schedules_window_pair_check
      CHECK ((window_start_minute IS NULL) = (window_end_minute IS NULL))
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS scan_schedules_window_pair_check`);
  await pgm.db.query(`
    ALTER TABLE scan_schedules
      DROP COLUMN IF EXISTS window_start_minute,
      DROP COLUMN IF EXISTS window_end_minute,
      DROP COLUMN IF EXISTS window_days,
      DROP COLUMN IF EXISTS window_timezone
  `);
};
