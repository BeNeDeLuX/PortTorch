/* eslint-disable */
exports.shorthands = undefined;

/**
 * Alerts for things that stop existing.
 *
 * Every webhook event so far is additive - host.new, port.opened,
 * nuclei.finding - so the platform was loud about what appeared and
 * completely silent about what vanished. Two cases that matters for:
 *
 *  - A scanner that simply stops polling. scan.stale only covers a job
 *    stuck mid-run and scan_queue.backlog only fires once work piles up,
 *    so a scanner with no running scan and an empty queue could be dead
 *    for weeks with nothing said. Fleet Health shows it, but only to
 *    whoever happens to open that page.
 *  - A host that stops responding - decommissioned (fine) or down (not
 *    fine), and today only visible by looking at last_seen_at by hand.
 *
 * Both follow the queue_backlog_alert_sent_at idiom rather than the
 * stale_alert_sent_at one: these are ongoing conditions that can end, so
 * the flag is cleared again when the thing comes back, letting a future
 * outage alert instead of being permanently silenced by one past one.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE scanner_agents ADD COLUMN offline_alert_sent_at timestamptz
  `);
  await pgm.db.query(`
    ALTER TABLE hosts ADD COLUMN disappeared_alert_sent_at timestamptz
  `);
  await pgm.db.query(`
    ALTER TABLE app_settings
      ADD COLUMN scanner_offline_threshold_minutes integer NOT NULL DEFAULT 30,
      ADD COLUMN host_disappeared_threshold_days integer NOT NULL DEFAULT 14
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE app_settings
      DROP COLUMN IF EXISTS scanner_offline_threshold_minutes,
      DROP COLUMN IF EXISTS host_disappeared_threshold_days
  `);
  await pgm.db.query(`ALTER TABLE hosts DROP COLUMN IF EXISTS disappeared_alert_sent_at`);
  await pgm.db.query(`ALTER TABLE scanner_agents DROP COLUMN IF EXISTS offline_alert_sent_at`);
};
