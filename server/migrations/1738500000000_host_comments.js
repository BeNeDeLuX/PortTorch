/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE host_comments (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      author text NOT NULL,
      body text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX host_comments_host_id_idx ON host_comments (host_id, created_at);

    INSERT INTO host_comments (host_id, author, body, created_at)
      SELECT id, 'migration', notes, now() FROM hosts WHERE notes IS NOT NULL AND notes <> '';

    ALTER TABLE hosts
      DROP COLUMN notes;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE hosts
      ADD COLUMN notes text;

    DROP TABLE IF EXISTS host_comments;
  `);
};
