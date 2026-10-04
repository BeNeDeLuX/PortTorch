/* eslint-disable */
exports.shorthands = undefined;

// Scanner visibility from SSO groups (auth/oidc.ts).
//
// oidc_scanner_groups: a provider group grants visibility of a scanner.
// group_name is stored lower-cased, since role mapping already compares
// group names case-insensitively and the two must not disagree.
//
// When any mapping exists, an SSO user's user_scanner_agents rows are
// replaced at every sign-in by the union of their groups' scanners - the
// provider becomes the source of truth for access, as it already is for
// the role. With no mappings at all, assignments stay the manual ones.
//
// app_settings.oidc_scanner_unmatched decides what a non-admin SSO user in
// none of the mapped groups gets. 'all' keeps today's meaning of "no
// assignment rows" (sees every scanner); 'deny' refuses the sign-in.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE oidc_scanner_groups (
      group_name text NOT NULL CHECK (group_name = lower(group_name) AND group_name <> ''),
      scanner_agent_id uuid NOT NULL REFERENCES scanner_agents(id) ON DELETE CASCADE,
      PRIMARY KEY (group_name, scanner_agent_id)
    );
    ALTER TABLE app_settings
      ADD COLUMN oidc_scanner_unmatched text NOT NULL DEFAULT 'all' CHECK (oidc_scanner_unmatched IN ('all', 'deny'));
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE app_settings DROP COLUMN oidc_scanner_unmatched;
    DROP TABLE oidc_scanner_groups;
  `);
};
