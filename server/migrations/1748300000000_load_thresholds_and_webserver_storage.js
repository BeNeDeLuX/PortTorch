/* eslint-disable */
exports.shorthands = undefined;

// Two things that belong together because they share the disk threshold.
//
// The load alert thresholds were constants: 90% CPU, 90% memory, 10% disk
// free. On a small host 10% of a 45 GB disk is 4.5 GB, which is too little
// warning; on a large one it is plenty. Now admin settings, defaulting to
// the old constants so nothing changes on upgrade. disk_low_percent is
// used for the scanners and for the webserver's own disk alike.
//
// The webserver's own disk: the database, screenshots and backups live
// there, and a full disk stops Postgres before anything else notices.
// webserver_storage_samples keeps one row per day (the last measurement of
// that day), enough to show growth and estimate when the disk fills,
// without a per-minute series nobody needs for a figure that moves by the
// day. webserver_disk_alert_sent_at is the come-and-go dedup for
// webserver.disk_low, like scanner_agents.disk_alert_sent_at.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN cpu_alert_percent integer NOT NULL DEFAULT 90 CHECK (cpu_alert_percent BETWEEN 50 AND 100),
      ADD COLUMN mem_alert_percent integer NOT NULL DEFAULT 90 CHECK (mem_alert_percent BETWEEN 50 AND 100),
      ADD COLUMN disk_low_percent integer NOT NULL DEFAULT 10 CHECK (disk_low_percent BETWEEN 1 AND 50),
      ADD COLUMN webserver_disk_alert_sent_at timestamptz;

    CREATE TABLE webserver_storage_samples (
      day date PRIMARY KEY,
      measured_at timestamptz NOT NULL,
      db_bytes bigint NOT NULL,
      disk_free_bytes bigint,
      disk_total_bytes bigint
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE webserver_storage_samples;
    ALTER TABLE app_settings
      DROP COLUMN cpu_alert_percent, DROP COLUMN mem_alert_percent, DROP COLUMN disk_low_percent,
      DROP COLUMN webserver_disk_alert_sent_at;
  `);
};
