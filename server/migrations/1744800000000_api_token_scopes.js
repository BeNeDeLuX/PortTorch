/* eslint-disable */
exports.shorthands = undefined;

/**
 * Rights on an API token.
 *
 * A token was a name and an optional expiry and nothing else, while the
 * external API it unlocks can do considerably more than read: trigger a
 * rescan, cancel a running scan, queue an ad-hoc scan against an
 * arbitrary target, and delete triage decisions. So a token handed to a
 * dashboard panel or a reporting script could launch scans across the
 * network - the one thing a recon platform should be most careful about
 * handing out.
 *
 * scope is deliberately just two values rather than a per-endpoint
 * permission matrix. The meaningful line for this API is "can it change
 * anything or only look", and a matrix would be more surface to get
 * wrong than the thing it protects.
 *
 * Existing tokens default to 'read_write': a migration must not silently
 * break integrations that are working today. New tokens default to
 * 'read' in the *dashboard*, which is where least privilege belongs -
 * a deliberate difference, not an oversight.
 *
 * scanner_agent_ids mirrors user_scanner_agents' own convention: an empty
 * array means every scanner, exactly as it does for a dashboard user, so
 * a token can be confined to one network segment's results the same way
 * a person can be.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE api_tokens
      ADD COLUMN scope text NOT NULL DEFAULT 'read_write'
        CHECK (scope IN ('read', 'read_write')),
      ADD COLUMN scanner_agent_ids uuid[] NOT NULL DEFAULT '{}'
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`
    ALTER TABLE api_tokens
      DROP COLUMN IF EXISTS scope,
      DROP COLUMN IF EXISTS scanner_agent_ids
  `);
};
