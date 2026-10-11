/* eslint-disable */
exports.shorthands = undefined;

// Scanner host metrics (scannerMetrics/).
//
// scanner_metrics: one row per scanner per minute, as reported by the
// scanner itself (POST /api/ingest/metrics). Kept for
// app_settings.scanner_metrics_raw_days, which is what the short-range
// charts read.
//
// scanner_metrics_hourly: each complete hour rolled up - averages for the
// line and maxima for the peaks, since an average alone hides exactly the
// spike a capacity question is about. Kept for
// scanner_metrics_hourly_days, for the long-range charts.
//
// scanner_agents.resource_alert_sent_at: come-and-go dedup for
// scanner.resource_pressure, cleared when the pressure is gone.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scanner_metrics (
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      at timestamptz NOT NULL,
      cpu_percent real NOT NULL,
      mem_used_bytes bigint NOT NULL,
      mem_total_bytes bigint NOT NULL,
      net_rx_bps double precision NOT NULL,
      net_tx_bps double precision NOT NULL,
      load1 real NOT NULL,
      scans_running integer NOT NULL,
      PRIMARY KEY (scanner_agent_id, at)
    );
    CREATE INDEX scanner_metrics_at_idx ON scanner_metrics (at);

    CREATE TABLE scanner_metrics_hourly (
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      hour timestamptz NOT NULL,
      samples integer NOT NULL,
      cpu_avg real NOT NULL,
      cpu_max real NOT NULL,
      mem_used_avg double precision NOT NULL,
      mem_used_max bigint NOT NULL,
      mem_total bigint NOT NULL,
      net_rx_avg double precision NOT NULL,
      net_rx_max double precision NOT NULL,
      net_tx_avg double precision NOT NULL,
      net_tx_max double precision NOT NULL,
      load1_avg real NOT NULL,
      scans_max integer NOT NULL,
      PRIMARY KEY (scanner_agent_id, hour)
    );

    ALTER TABLE app_settings
      ADD COLUMN scanner_metrics_raw_days integer NOT NULL DEFAULT 14 CHECK (scanner_metrics_raw_days BETWEEN 1 AND 90),
      ADD COLUMN scanner_metrics_hourly_days integer NOT NULL DEFAULT 365 CHECK (scanner_metrics_hourly_days BETWEEN 7 AND 1825);

    ALTER TABLE scanner_agents ADD COLUMN resource_alert_sent_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents DROP COLUMN resource_alert_sent_at;
    ALTER TABLE app_settings DROP COLUMN scanner_metrics_hourly_days, DROP COLUMN scanner_metrics_raw_days;
    DROP TABLE scanner_metrics_hourly;
    DROP TABLE scanner_metrics;
  `);
};
