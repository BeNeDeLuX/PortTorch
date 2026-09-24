/* eslint-disable */
exports.shorthands = undefined;

// Fleet Health can report duplicate scanner coverage but had no way to
// hear "yes, we know". On a real deployment the duplication turned out to
// be one scanner's three-week-old rows for a range another scanner now
// covers nightly - correct to flag, and nothing the operator wanted to
// act on beyond letting retention take them, which was 160 days away. The
// card would simply have stayed yellow for five months, which is how a
// warning stops being read.
//
// Deliberately time-boxed, mirroring finding_triage.review_at: an
// acknowledgement that never expires recreates the problem it solves.
//
// ack_count is what keeps this from being a blanket mute. It stores how
// many duplicated addresses were accepted, and the acknowledgement stops
// suppressing once the current number exceeds it - a *growing* overlap is
// news even while the known one is accepted. Same idea as
// ssh_shared_key_alerts storing ip_count so a group that gains a member
// alerts again.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      ADD COLUMN duplicate_coverage_ack_until timestamptz,
      ADD COLUMN duplicate_coverage_ack_count integer,
      ADD COLUMN duplicate_coverage_ack_by text
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings
      DROP COLUMN duplicate_coverage_ack_until,
      DROP COLUMN duplicate_coverage_ack_count,
      DROP COLUMN duplicate_coverage_ack_by
  `);
};
