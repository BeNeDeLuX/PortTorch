/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE saved_searches (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      filters jsonb NOT NULL,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    -- Tracks which hosts currently match a saved search, so the periodic
    -- checker (server/src/savedSearches/checker.ts) can diff "matches now"
    -- against "matched last time" and only alert on genuinely new matches,
    -- not the same hosts over and over.
    CREATE TABLE saved_search_matches (
      saved_search_id uuid NOT NULL REFERENCES saved_searches(id) ON DELETE CASCADE,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      PRIMARY KEY (saved_search_id, host_id)
    );
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS saved_search_matches;
    DROP TABLE IF EXISTS saved_searches;
  `);
};
