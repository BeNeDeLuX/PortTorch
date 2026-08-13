/* eslint-disable */
exports.shorthands = undefined;

// Scan Profiles: which NSE scripts a scan actually runs is now a choice
// ("Default" - today's unchanged hardcoded list, "All Safe Modules" - a
// broader, still read-only/safe nmap category, or "Custom" - a named,
// admin-managed script list), not a fixed compile-time constant. See
// scanner/internal/pipeline/nse_default_scripts.go/nse_safe_scripts.go
// for where "Default"/"All Safe Modules" are actually resolved - the
// canonical, executable script lists live only in the Go scanner, never
// duplicated here, so the webserver only ever stores/transmits a
// symbolic profile kind plus (for Custom only) the user-authored list.
//
// nse_scripts/nse_profile_label on scan_requests/scan_schedules are
// resolved SNAPSHOTS captured at request/schedule-creation time, not a
// live join against scan_profiles - deliberately, so editing or deleting
// a custom profile later can never retroactively change an already-
// queued scan request or an already-fired schedule's history. This is
// also what makes a hard DELETE on scan_profiles safe, unlike most other
// entities in this codebase - there is nothing for it to orphan.
//
// DEFAULT 'default' + nullable nse_scripts means every pre-existing row
// (and any row inserted by a caller that doesn't know about profiles -
// the External API's rescan endpoint, or an un-upgraded scanner) is
// unaffected: nse_profile='default', nse_scripts=NULL resolves scanner-
// side to exactly today's hardcoded script list (see resolveNSEScripts
// in scanner/internal/api/server.go).
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE scan_profiles (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text UNIQUE NOT NULL,
      nse_scripts text[] NOT NULL,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE scan_requests
      ADD COLUMN nse_profile text NOT NULL DEFAULT 'default'
        CHECK (nse_profile IN ('default', 'all_safe', 'custom')),
      ADD COLUMN nse_scripts text[],
      ADD COLUMN nse_profile_label text;

    ALTER TABLE scan_schedules
      ADD COLUMN nse_profile text NOT NULL DEFAULT 'default'
        CHECK (nse_profile IN ('default', 'all_safe', 'custom')),
      ADD COLUMN nse_scripts text[],
      ADD COLUMN nse_profile_label text;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE scan_schedules
      DROP COLUMN nse_profile,
      DROP COLUMN nse_scripts,
      DROP COLUMN nse_profile_label;

    ALTER TABLE scan_requests
      DROP COLUMN nse_profile,
      DROP COLUMN nse_scripts,
      DROP COLUMN nse_profile_label;

    DROP TABLE IF EXISTS scan_profiles;
  `);
};
