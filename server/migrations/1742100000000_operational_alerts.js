/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Dedup state for the new scan.stale webhook (see
    -- src/webhooks/operationalAlerts.ts) - a scan_jobs row is created
    -- fresh per scan and either finishes normally (leaving the "running"
    -- status this check filters on) or stays stuck forever, so "fire
    -- once, forever" is correct here, same idiom as
    -- tls_certificates.expiry_alert_sent_at.
    ALTER TABLE scan_jobs
      ADD COLUMN stale_alert_sent_at timestamptz;

    -- Dedup state for the new scan_queue.backlog webhook. Unlike the
    -- column above, a queue backlog is a recurring condition (a scanner
    -- can fall behind, catch up, then fall behind again later) rather
    -- than a one-time event - operationalAlerts.ts clears this back to
    -- NULL once that scanner no longer has an aged backlog, so a future
    -- one can alert again instead of being permanently silenced by one
    -- past incident.
    ALTER TABLE scanner_agents
      ADD COLUMN queue_backlog_alert_sent_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_jobs DROP COLUMN IF EXISTS stale_alert_sent_at;
    ALTER TABLE scanner_agents DROP COLUMN IF EXISTS queue_backlog_alert_sent_at;
  `);
};
