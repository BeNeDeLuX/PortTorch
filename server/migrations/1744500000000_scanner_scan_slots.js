/* eslint-disable */
exports.shorthands = undefined;

/**
 * How busy a scanner actually is.
 *
 * maxConcurrentScans made a scanner's capacity a real number, but the
 * webserver had no way to know it: the setting lives in that host's
 * config.yaml, and the webserver only ever sees it when an admin happens
 * to have set it as a dashboard override. So "is this scanner saturated
 * or idle?" - the question you need answered before queueing more work -
 * was unanswerable from here.
 *
 * The scanner reports both numbers on every authenticated request
 * (X-Scanner-Scan-Slots: running/max), the same piggyback mechanism that
 * already carries version and submit_queue_pending. NULL means unknown -
 * a scanner build older than the header, or a one-shot "scan"/"menu"
 * process that has no slots at all - which is deliberately distinct from
 * a reported 0.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE scanner_agents
      ADD COLUMN scan_slots_running integer,
      ADD COLUMN scan_slots_max integer
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE scanner_agents
      DROP COLUMN IF EXISTS scan_slots_running,
      DROP COLUMN IF EXISTS scan_slots_max
  `);
};
