/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Admin-triggered "refresh this scanner's nuclei templates" request.
    -- Structurally identical to the self-update columns added in
    -- 1741900000000_scanner_self_update.js, and for the same reason: the
    -- webserver can never push to a scanner (all communication is
    -- scanner-initiated), so this is a flag the scanner's own watcher
    -- polls for on its next tick. Deliberately its own set of columns
    -- rather than reusing the self-update ones - the two are independent
    -- actions that can legitimately be outstanding at the same time, and
    -- a shared status column couldn't represent that.
    ALTER TABLE scanner_agents
      ADD COLUMN template_update_requested_at timestamptz,
      ADD COLUMN template_update_status text CHECK (template_update_status IN ('pending', 'failed')),
      ADD COLUMN template_update_failure_reason text,
      ADD COLUMN template_update_attempt_count integer NOT NULL DEFAULT 0;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      DROP COLUMN IF EXISTS template_update_requested_at,
      DROP COLUMN IF EXISTS template_update_status,
      DROP COLUMN IF EXISTS template_update_failure_reason,
      DROP COLUMN IF EXISTS template_update_attempt_count;
  `);
};
