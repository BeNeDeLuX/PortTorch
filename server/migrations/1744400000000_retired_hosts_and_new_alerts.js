/* eslint-disable */
exports.shorthands = undefined;

/**
 * Two gaps the previous round left behind.
 *
 * hosts.retired_at: host.disappeared says "decommissioned, or down" and
 * had no way to answer the first case. A deliberately switched-off server
 * alerted indefinitely, and the only way to stop it was deleting the host
 * - which throws away its entire observation history. Retiring says "I
 * know, stop telling me" while keeping everything that was ever recorded.
 * Deliberately narrow: it suppresses host.disappeared and nothing else.
 * If something on a retired host opens a port again, that is still worth
 * hearing about.
 *
 * The two alert flags follow the come-and-go idiom
 * (queue_backlog_alert_sent_at / offline_alert_sent_at), not the fire-once
 * one: both conditions can end, and a range that goes stale a second time
 * should alert a second time rather than being silenced by one past
 * incident.
 *
 * ssh_shared_key_alerts is its own table rather than a column because the
 * thing being alerted on isn't a row anywhere - it's a fingerprint shared
 * across several hosts, which belongs to no single one of them. Keeping
 * ip_count lets the alert fire again when the count *grows* (a third
 * machine turning up with the same key is news, even after the first two
 * were reported) without re-firing on every check.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`ALTER TABLE hosts ADD COLUMN retired_at timestamptz`);
  await pgm.db.query(`ALTER TABLE monitored_networks ADD COLUMN coverage_alert_sent_at timestamptz`);
  await pgm.db.query(`
    CREATE TABLE ssh_shared_key_alerts (
      fingerprint_sha256 text PRIMARY KEY,
      ip_count integer NOT NULL,
      alerted_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`DROP TABLE IF EXISTS ssh_shared_key_alerts`);
  await pgm.db.query(`ALTER TABLE monitored_networks DROP COLUMN IF EXISTS coverage_alert_sent_at`);
  await pgm.db.query(`ALTER TABLE hosts DROP COLUMN IF EXISTS retired_at`);
};
