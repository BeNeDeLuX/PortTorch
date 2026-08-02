/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE tls_certificates (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      subject_cn text,
      issuer_cn text,
      san_list text[],
      not_before timestamptz,
      not_after timestamptz,
      fingerprint_sha256 text NOT NULL,
      signature_algorithm text,
      self_signed boolean NOT NULL DEFAULT false,
      captured_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX tls_certificates_host_id_idx ON tls_certificates (host_id);

    CREATE TABLE ssh_host_keys (
      id bigserial PRIMARY KEY,
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      key_type text NOT NULL,
      bits integer,
      fingerprint_md5 text,
      fingerprint_sha256 text NOT NULL,
      captured_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ssh_host_keys_host_id_idx ON ssh_host_keys (host_id);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS ssh_host_keys;
    DROP TABLE IF EXISTS tls_certificates;
  `);
};
