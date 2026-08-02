/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE rdp_screenshots (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      image_path text NOT NULL,
      captured_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX rdp_screenshots_host_id_idx ON rdp_screenshots (host_id);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS rdp_screenshots;
  `);
};
