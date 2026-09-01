/* eslint-disable */
exports.shorthands = undefined;

/**
 * What a scanner's own config.yaml actually says.
 *
 * The Configure dialog could only ever show the *shipped* default beside
 * each field, because the webserver cannot read a file on the scanner's
 * host - so an operator who had tuned that file saw a number that did not
 * apply to their scanner, which is exactly the field where it matters
 * (leaving it blank means "use whatever the file says").
 *
 * The scanner now reports those values itself, once per process, over
 * PUT /api/ingest/config-report. Deliberately the *base* config rather
 * than the effective one: the dialog's question is "what applies if I
 * leave this blank", and the effective config already has any dashboard
 * override folded in - reporting that would make an override look like
 * the file's own value, with nothing left to clear back to.
 *
 * NULL means unknown - an older scanner build, or one that has not
 * reported yet - which the dialog shows differently from a known value
 * rather than pretending the shipped default is this scanner's.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scanner_agents ADD COLUMN base_config jsonb`);
};

exports.down = async (pgm) => {
  await pgm.db.query(`ALTER TABLE scanner_agents DROP COLUMN IF EXISTS base_config`);
};
