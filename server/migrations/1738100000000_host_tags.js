/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE host_tags (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      tag text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (host_id, tag)
    );
    CREATE INDEX host_tags_tag_idx ON host_tags (tag);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS host_tags;
  `);
};
