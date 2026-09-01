/* eslint-disable */
exports.shorthands = undefined;

/**
 * The third outbound integration gets the same TLS treatment as the other
 * two, and a CA-expiry alert so the trust anchors don't lapse silently.
 *
 * webhooks.verify_tls: alert targets are very often internally hosted -
 * a Mattermost, a Rocket.Chat, an internal automation endpoint - and
 * until now they were the one outbound integration with neither a CA
 * bundle nor a way to relax verification. The bundle covers the good
 * case; this covers the rest, defaulting to verifying like the others.
 *
 * trusted_ca_certificates.expiry_alert_sent_at: an expiring CA is a
 * uniquely unpleasant failure because it takes out mail *and* SIEM
 * delivery at the same moment, and the only existing warning was the row
 * turning red on a settings page nobody has reason to open. Fire-once
 * (like tls_certificates.expiry_alert_sent_at), not come-and-go: a
 * certificate's expiry only moves in one direction, so there is no
 * recovery to detect - replacing it means uploading a new row.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`ALTER TABLE webhooks ADD COLUMN verify_tls boolean NOT NULL DEFAULT true`);
  await pgm.db.query(`ALTER TABLE trusted_ca_certificates ADD COLUMN expiry_alert_sent_at timestamptz`);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE trusted_ca_certificates DROP COLUMN IF EXISTS expiry_alert_sent_at`);
  await pgm.db.query(`ALTER TABLE webhooks DROP COLUMN IF EXISTS verify_tls`);
};
