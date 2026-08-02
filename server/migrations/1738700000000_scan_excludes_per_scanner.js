/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_excludes
      DROP CONSTRAINT scan_excludes_kind_value_key,
      ADD COLUMN scanner_agent_id uuid REFERENCES scanner_agents(id) ON DELETE CASCADE;

    -- Partial unique indexes instead of one plain UNIQUE(kind, value,
    -- scanner_agent_id): Postgres treats every NULL as distinct in a
    -- regular unique constraint, so two identical global excludes
    -- (scanner_agent_id IS NULL) wouldn't be caught by that alone.
    CREATE UNIQUE INDEX scan_excludes_global_unique ON scan_excludes (kind, value) WHERE scanner_agent_id IS NULL;
    CREATE UNIQUE INDEX scan_excludes_scanner_unique ON scan_excludes (kind, value, scanner_agent_id) WHERE scanner_agent_id IS NOT NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP INDEX IF EXISTS scan_excludes_scanner_unique;
    DROP INDEX IF EXISTS scan_excludes_global_unique;

    ALTER TABLE scan_excludes
      DROP COLUMN scanner_agent_id,
      ADD CONSTRAINT scan_excludes_kind_value_key UNIQUE (kind, value);
  `);
};
