/* eslint-disable */
exports.shorthands = undefined;

/**
 * Shipping the audit trail and the scanners' own scan logs to a SIEM over
 * an HTTP Event Collector (Splunk HEC and the many collectors that speak
 * its shape).
 *
 * Both streams already exist as durable tables - audit_log and
 * scan_job_full_log - and that is what makes this a *cursor* rather than
 * a fire-and-forget hook on the write path. A SIEM feed with silent gaps
 * is worse than no feed: an operator who sees events arriving assumes
 * they are seeing everything. With a cursor, a collector that is down for
 * ten minutes simply causes the next tick to catch up, and nothing is
 * reported as delivered that wasn't.
 *
 * The two cursors have different shapes because the tables do:
 *
 *  - audit_log has a bigserial id, monotonic and gap-tolerant, so
 *    "everything after id N" is exact.
 *  - scan_job_full_log is keyed by scan_job_id and written once when a
 *    scan finishes (with an upsert that bumps created_at if the same job
 *    uploads again), so the cursor is (created_at, scan_job_id) - the
 *    timestamp alone would either skip or repeat rows sharing one.
 *
 * The token is stored like smtp_password: written but never returned by
 * the settings API, so an admin who can already change it cannot read
 * back a credential someone else set.
 *
 * Honest limitation, documented rather than papered over: retention
 * (retention.ts) deletes old audit rows and old scan logs on its own
 * schedule. If the collector is unreachable for longer than the retention
 * window, those events are gone before they were ever forwarded - the
 * cursor then simply resumes at what still exists rather than blocking
 * forever on rows that no longer do.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE app_settings
      ADD COLUMN hec_url text,
      ADD COLUMN hec_token text,
      ADD COLUMN hec_audit_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN hec_scan_log_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN hec_index text,
      ADD COLUMN hec_sourcetype text,
      -- Self-signed certificates are the norm on an internally hosted
      -- collector, so this has to be switchable - defaulting to verifying.
      ADD COLUMN hec_verify_tls boolean NOT NULL DEFAULT true
  `);

  await pgm.db.query(`
    CREATE TABLE hec_state (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      audit_cursor bigint,
      scan_log_cursor_at timestamptz,
      scan_log_cursor_job_id uuid,
      last_success_at timestamptz,
      last_attempt_at timestamptz,
      last_error text,
      events_forwarded bigint NOT NULL DEFAULT 0
    );
    INSERT INTO hec_state (id) VALUES (1);
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`DROP TABLE IF EXISTS hec_state`);
  await pgm.db.query(`
    ALTER TABLE app_settings
      DROP COLUMN IF EXISTS hec_url,
      DROP COLUMN IF EXISTS hec_token,
      DROP COLUMN IF EXISTS hec_audit_enabled,
      DROP COLUMN IF EXISTS hec_scan_log_enabled,
      DROP COLUMN IF EXISTS hec_index,
      DROP COLUMN IF EXISTS hec_sourcetype,
      DROP COLUMN IF EXISTS hec_verify_tls
  `);
};
