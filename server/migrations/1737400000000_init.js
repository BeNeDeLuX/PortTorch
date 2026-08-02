/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE users (
      id serial PRIMARY KEY,
      username text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      role text NOT NULL DEFAULT 'admin',
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE scanner_agents (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text UNIQUE NOT NULL,
      api_key_hash text NOT NULL,
      last_seen_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX scanner_agents_api_key_hash_idx ON scanner_agents (api_key_hash);

    CREATE TABLE scan_jobs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      target_spec text NOT NULL,
      port_spec text NOT NULL,
      status text NOT NULL DEFAULT 'running',
      started_at timestamptz NOT NULL DEFAULT now(),
      finished_at timestamptz
    );
    CREATE INDEX scan_jobs_scanner_agent_id_idx ON scan_jobs (scanner_agent_id);

    CREATE TABLE hosts (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      ip inet UNIQUE NOT NULL,
      hostname text,
      first_seen_at timestamptz NOT NULL DEFAULT now(),
      last_seen_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE host_port_observations (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      protocol text NOT NULL DEFAULT 'tcp',
      state text NOT NULL DEFAULT 'open',
      service_name text,
      service_product text,
      service_version text,
      banner text,
      observed_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX host_port_observations_host_port_idx ON host_port_observations (host_id, port, protocol);
    CREATE INDEX host_port_observations_scan_job_idx ON host_port_observations (scan_job_id);
    CREATE INDEX host_port_observations_search_idx ON host_port_observations
      USING GIN (to_tsvector('simple',
        coalesce(service_name, '') || ' ' ||
        coalesce(service_product, '') || ' ' ||
        coalesce(service_version, '') || ' ' ||
        coalesce(banner, '')
      ));

    CREATE VIEW current_host_ports AS
      SELECT DISTINCT ON (host_id, port, protocol) *
      FROM host_port_observations
      ORDER BY host_id, port, protocol, observed_at DESC;

    CREATE TABLE screenshots (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      url text NOT NULL,
      image_path text NOT NULL,
      http_status integer,
      page_title text,
      captured_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX screenshots_host_id_idx ON screenshots (host_id);

    -- Session table in the schema expected by connect-pg-simple
    CREATE TABLE session (
      sid varchar NOT NULL COLLATE "default",
      sess json NOT NULL,
      expire timestamp(6) NOT NULL
    ) WITH (OIDS = FALSE);
    ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE;
    CREATE INDEX "IDX_session_expire" ON session (expire);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS session;
    DROP TABLE IF EXISTS screenshots;
    DROP VIEW IF EXISTS current_host_ports;
    DROP TABLE IF EXISTS host_port_observations;
    DROP TABLE IF EXISTS hosts;
    DROP TABLE IF EXISTS scan_jobs;
    DROP TABLE IF EXISTS scanner_agents;
    DROP TABLE IF EXISTS users;
  `);
};
