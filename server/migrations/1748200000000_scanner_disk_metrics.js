/* eslint-disable */
exports.shorthands = undefined;

// Free space on the scanner host, reported from scanner 0.31.0 with every
// metrics sample: the fullest filesystem among the scanner's submit queue
// and its temp directory, where screenshots and scan output are staged. A
// full disk there makes scans fail quietly, so it gets a chart and an
// alert of its own.
//
// Nullable: an older scanner sends none, and a gap must read as "not
// reported", never as "empty disk". The hourly roll-up keeps the minimum
// free - the moment closest to running out is the one that matters.
// scanner_agents.disk_alert_sent_at is the come-and-go dedup for
// scanner.disk_low, like resource_alert_sent_at beside it.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_metrics ADD COLUMN disk_free_bytes bigint, ADD COLUMN disk_total_bytes bigint;
    ALTER TABLE scanner_metrics_hourly ADD COLUMN disk_free_min bigint, ADD COLUMN disk_total bigint;
    ALTER TABLE scanner_agents ADD COLUMN disk_alert_sent_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents DROP COLUMN disk_alert_sent_at;
    ALTER TABLE scanner_metrics_hourly DROP COLUMN disk_free_min, DROP COLUMN disk_total;
    ALTER TABLE scanner_metrics DROP COLUMN disk_free_bytes, DROP COLUMN disk_total_bytes;
  `);
};
