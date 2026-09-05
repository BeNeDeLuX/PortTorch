exports.up = (pgm) => {
  pgm.sql(`
    -- Singleton (id always 1) cache of the newest published webserver
    -- image tag, synced from Docker Hub - same idiom and same reasoning
    -- as scanner_release_cache next to it: avoid a live registry call on
    -- every dashboard load of Fleet Health.
    --
    -- Docker Hub rather than GitHub, unlike the scanner's: the webserver
    -- has no tag-triggered release workflow at all (see the root
    -- CLAUDE.md's Versioning section) - its image is built and pushed on
    -- every master push touching server/**, tagged with package.json's
    -- version. The registry is therefore the only place that knows what
    -- is actually deployable, and it is also where the operator pulls
    -- from, so it is the honest thing to compare against.
    CREATE TABLE webserver_release_cache (
      id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      latest_version text,
      image_tag text,
      published_at timestamptz,
      synced_at timestamptz,
      -- Why the last sync failed, kept so the dashboard can say "we don't
      -- know" and why, rather than silently showing a stale version as
      -- current. Null while the last attempt succeeded.
      last_error text
    );
    INSERT INTO webserver_release_cache (id) VALUES (1);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`DROP TABLE webserver_release_cache;`);
};
