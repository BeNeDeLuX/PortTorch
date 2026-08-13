/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    -- Singleton row (id always 1) caching the latest published scanner
    -- release, synced hourly from GitHub (see src/scannerUpdate/githubSync.ts)
    -- - same idiom as digest_email_state, avoiding a live GitHub API call
    -- on every scanner poll / every dashboard load of Scanner Agents.
    CREATE TABLE scanner_release_cache (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      latest_version text,
      latest_tag text,
      release_url text,
      synced_at timestamptz
    );
    INSERT INTO scanner_release_cache (id, latest_version, latest_tag, release_url, synced_at)
    VALUES (1, NULL, NULL, NULL, NULL);

    ALTER TABLE scanner_agents
      ADD COLUMN update_requested_at timestamptz,
      ADD COLUMN update_request_status text CHECK (update_request_status IN ('pending', 'failed')),
      ADD COLUMN update_failure_reason text,
      ADD COLUMN update_attempt_count integer NOT NULL DEFAULT 0;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents
      DROP COLUMN IF EXISTS update_requested_at,
      DROP COLUMN IF EXISTS update_request_status,
      DROP COLUMN IF EXISTS update_failure_reason,
      DROP COLUMN IF EXISTS update_attempt_count;
    DROP TABLE IF EXISTS scanner_release_cache;
  `);
};
