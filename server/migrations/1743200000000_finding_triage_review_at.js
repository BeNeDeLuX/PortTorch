/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // An expiry date for a triage decision. Without one, "accepted risk"
  // silently meant "accepted forever" - which recreates the exact problem
  // triage was built to solve: a finding disappears from view and nobody
  // ever looks at it again. Time-boxed acceptance ("we'll live with this
  // until the vendor patch lands in Q3") is the normal case in
  // vulnerability management; permanent acceptance is the exception.
  //
  // Deliberately allowed on any state rather than only accepted_risk, so
  // the column means one simple thing - "this decision stops applying
  // after this instant" - instead of needing a per-state special case.
  // It's genuinely useful beyond accepted_risk too: a "fixed" call can be
  // given a date to re-confirm the fix actually held.
  //
  // NULL means the decision doesn't expire, matching the
  // absence-means-default idiom used by api_tokens.expires_at and
  // scan_excludes.scanner_agent_id.
  //
  // The row is deliberately NOT deleted once it expires - who accepted
  // what, when, and why is exactly the history worth keeping, and the
  // audit trail would be poorer for dropping it. Expiry only stops the
  // decision from being *honored*; queries treat an expired row as if it
  // weren't there.
  pgm.sql(`
    ALTER TABLE finding_triage ADD COLUMN review_at timestamptz;
    -- Partial: only expiring rows are ever scanned for "review due", and
    -- the overwhelming majority won't have a date set.
    CREATE INDEX finding_triage_review_at_idx ON finding_triage (review_at) WHERE review_at IS NOT NULL;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP INDEX IF EXISTS finding_triage_review_at_idx;
    ALTER TABLE finding_triage DROP COLUMN IF EXISTS review_at;
  `);
};
