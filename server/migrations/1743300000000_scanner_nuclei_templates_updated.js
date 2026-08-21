/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // nuclei's templates are fetched once by install.sh and never refreshed
  // automatically (a deliberate choice - a scanner pulling new check
  // logic from the internet unattended is a policy decision). The
  // consequence is silent: a scan with year-old templates looks exactly
  // like one with current templates, it just stops finding anything
  // newer. Recording when each scanner last updated them is what makes
  // that visible.
  //
  // NULL means unknown - either nuclei isn't installed on that scanner,
  // or it's running a build predating the reporting header. Deliberately
  // distinct from "very old", since only one of those is worth alerting
  // on, and it's never cleared once set (see apiKeyAuth.ts).
  pgm.sql(`
    ALTER TABLE scanner_agents ADD COLUMN nuclei_templates_updated_at timestamptz;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scanner_agents DROP COLUMN IF EXISTS nuclei_templates_updated_at;
  `);
};
