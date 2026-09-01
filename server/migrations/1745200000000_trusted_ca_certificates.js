/* eslint-disable */
exports.shorthands = undefined;

/**
 * Trusting an internal CA, rather than switching verification off.
 *
 * smtp_verify_tls / hec_verify_tls exist because an internally hosted
 * mail relay or log collector usually presents a certificate this
 * webserver has no reason to trust. Turning verification off works, but
 * it is the blunt answer: it accepts *any* certificate, including one
 * swapped in by whoever sits between the two hosts. Uploading the CA that
 * actually signed it keeps verification on and still succeeds.
 *
 * A table rather than a settings column: an organisation can easily have
 * a root and an issuing CA, or be mid-rotation with two roots live at
 * once, and one text field would make that a copy-paste-two-PEMs-together
 * exercise with no way to see or remove either afterwards.
 *
 * subject/not_after/fingerprint are extracted at upload time and stored
 * alongside the PEM. They are not the source of truth - the PEM is - but
 * an admin looking at this list a year later needs to know what each
 * entry is and when it stops working without pasting it into a tool.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    CREATE TABLE trusted_ca_certificates (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      pem text NOT NULL,
      subject text,
      issuer text,
      not_before timestamptz,
      not_after timestamptz,
      fingerprint_sha256 text NOT NULL UNIQUE,
      uploaded_by text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`DROP TABLE IF EXISTS trusted_ca_certificates`);
};
