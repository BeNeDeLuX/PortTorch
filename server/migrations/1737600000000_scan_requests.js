/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_schedules (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      target_spec text NOT NULL,
      port_spec text NOT NULL,
      interval_minutes integer NOT NULL CHECK (interval_minutes > 0),
      enabled boolean NOT NULL DEFAULT true,
      next_run_at timestamptz NOT NULL DEFAULT now(),
      last_run_at timestamptz,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX scan_schedules_due_idx ON scan_schedules (next_run_at) WHERE enabled;

    CREATE TABLE scan_requests (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      host_id uuid REFERENCES hosts(id) ON DELETE SET NULL,
      target_spec text NOT NULL,
      port_spec text NOT NULL,
      status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'completed', 'failed')),
      scan_job_id uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
      requested_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      claimed_at timestamptz,
      completed_at timestamptz
    );
    CREATE INDEX scan_requests_pending_idx ON scan_requests (scanner_agent_id, created_at) WHERE status = 'pending';
    CREATE INDEX scan_requests_host_id_idx ON scan_requests (host_id);

    ALTER TABLE screenshots
      ADD COLUMN tls_protocol text,
      ADD COLUMN tls_cipher text,
      ADD COLUMN tls_subject text,
      ADD COLUMN tls_issuer text,
      ADD COLUMN tls_valid_from timestamptz,
      ADD COLUMN tls_valid_to timestamptz,
      ADD COLUMN technologies text[];
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE screenshots
      DROP COLUMN IF EXISTS tls_protocol,
      DROP COLUMN IF EXISTS tls_cipher,
      DROP COLUMN IF EXISTS tls_subject,
      DROP COLUMN IF EXISTS tls_issuer,
      DROP COLUMN IF EXISTS tls_valid_from,
      DROP COLUMN IF EXISTS tls_valid_to,
      DROP COLUMN IF EXISTS technologies;
    DROP TABLE IF EXISTS scan_requests;
    DROP TABLE IF EXISTS scan_schedules;
  `);
};
