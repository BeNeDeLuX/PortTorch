/* eslint-disable */
exports.shorthands = undefined;

/**
 * Narrowing an alert channel to what it is actually meant to hear.
 *
 * A channel was a name, a type and a list of event names. In a fleet
 * large enough to need alerting, that is the same thing as no filter at
 * all: nuclei.finding fires for every new match including nuclei's own
 * very numerous "info" ones, and port.opened fires for every port on
 * every host regardless of which network it is on. A channel nobody can
 * narrow is a channel somebody eventually mutes, and a muted channel is
 * worse than none - it still looks configured.
 *
 * Three filters, all empty-means-everything so every existing channel
 * keeps behaving exactly as it did:
 *
 *  - filter_scanner_agent_ids: the network the event came from.
 *  - filter_tags: the host's own tags - "only what we tagged prod".
 *  - min_severity: for the events that carry one (nuclei findings, CVE
 *    alerts). Stored as the name, not an ordinal, so the column reads the
 *    same as everything else in the app; the ordering lives in code.
 *
 * The host-based filters only ever narrow *host-scoped* events. A
 * scanner.offline or scan_queue.backlog alert is about the fleet, not
 * about a host, so a tag filter must not swallow it - that would be an
 * operator quietly losing the alerts that matter most while believing
 * they had only narrowed the noisy ones. The scanner filter does apply to
 * scanner-scoped events, since those genuinely name a scanner.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE webhooks
      ADD COLUMN filter_scanner_agent_ids uuid[] NOT NULL DEFAULT '{}',
      ADD COLUMN filter_tags text[] NOT NULL DEFAULT '{}',
      ADD COLUMN min_severity text
        CHECK (min_severity IS NULL OR min_severity IN ('info', 'low', 'medium', 'high', 'critical'))
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE webhooks
      DROP COLUMN IF EXISTS filter_scanner_agent_ids,
      DROP COLUMN IF EXISTS filter_tags,
      DROP COLUMN IF EXISTS min_severity
  `);
};
