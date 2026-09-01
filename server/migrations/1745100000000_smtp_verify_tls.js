/* eslint-disable */
exports.shorthands = undefined;

/**
 * Letting an internal mail server present a self-signed certificate.
 *
 * nodemailer verifies the server's certificate chain by default, which is
 * right - but an internally hosted mail relay very often presents a
 * self-signed certificate or one from a private CA, and the failure looks
 * like "self-signed certificate in certificate chain" with no way to get
 * past it from the dashboard. The same situation the HEC collector
 * already has a switch for (hec_verify_tls), and it gets the same switch,
 * defaulting to verifying.
 *
 * Deliberately its own column rather than being folded into `secure`:
 * that one selects implicit TLS (port 465) versus STARTTLS, which is a
 * different question from whether the presented certificate is checked.
 * Conflating them would mean an admin on 587 could only stop the
 * verification error by also claiming the port speaks implicit TLS.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE app_settings ADD COLUMN smtp_verify_tls boolean NOT NULL DEFAULT true
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE app_settings DROP COLUMN IF EXISTS smtp_verify_tls`);
};
