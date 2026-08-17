/* eslint-disable */
exports.shorthands = undefined;

// Web-application vulnerability scanning via nuclei - a new, independent
// pipeline stage (scanner/internal/pipeline/nuclei.go) run against every
// HTTP(S) port a scan discovers, alongside gowitness's screenshot. Off by
// default, opt-in per scan/schedule (CHECK default 'off') - unlike NSE's
// "Default" tier (which always runs something), nuclei never ran before
// this existed at all, and its templates range from purely informational
// to genuinely intrusive.
//
// Same snapshot design as scan_profiles/nse_profile (see that migration's
// own comment for the full reasoning): nuclei_tags/nuclei_profile_label on
// scan_requests/scan_schedules are resolved at request/schedule-creation
// time, never a live join against nuclei_profiles - editing or deleting a
// custom profile later can never retroactively change an already-queued
// scan request or an already-fired schedule's history, and it's why a
// hard DELETE on nuclei_profiles is safe.
//
// One deliberate difference from scan_profiles: there is no
// nuclei_findings.severity/tag ALLOWLIST enforced here or in the TS
// validation layer the way KNOWN_NSE_SCRIPTS enforces script names -
// nuclei's own tag taxonomy has thousands of entries and grows with every
// template release (confirmed by testing: a real count against the
// downloaded template tree returned 7625 distinct tags), so an
// unrecognized tag is accepted and simply matches zero templates rather
// than being rejected - a materially different risk profile than nmap's
// --script=, where an unrecognized name is a hard error that aborts the
// whole run. Severity IS still constrained (see nucleiProfiles/routes.ts)
// since nuclei's severity enum is small and stable.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE TABLE nuclei_profiles (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text UNIQUE NOT NULL,
      tags text[] NOT NULL DEFAULT '{}',
      severities text[] NOT NULL DEFAULT '{}',
      excluded_tags text[] NOT NULL DEFAULT '{}',
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE scan_requests
      ADD COLUMN nuclei_profile text NOT NULL DEFAULT 'off'
        CHECK (nuclei_profile IN ('off', 'safe', 'custom')),
      ADD COLUMN nuclei_tags text[],
      ADD COLUMN nuclei_profile_label text;

    ALTER TABLE scan_schedules
      ADD COLUMN nuclei_profile text NOT NULL DEFAULT 'off'
        CHECK (nuclei_profile IN ('off', 'safe', 'custom')),
      ADD COLUMN nuclei_tags text[],
      ADD COLUMN nuclei_profile_label text;

    -- One row per matched nuclei template, not a JSON blob column - a
    -- finding needs to be fleet-wide filterable/sortable by severity/
    -- template id, the same reasoning that already makes ssh_host_keys a
    -- dedicated table rather than a column on host_port_observations.
    CREATE TABLE nuclei_findings (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      scan_job_id uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
      port integer NOT NULL,
      template_id text NOT NULL,
      name text NOT NULL,
      severity text NOT NULL,
      matched_at text NOT NULL,
      description text,
      reference text[],
      tags text[],
      curl_command text,
      observed_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE INDEX nuclei_findings_host_id_idx ON nuclei_findings (host_id);
    CREATE INDEX nuclei_findings_severity_idx ON nuclei_findings (severity);
    CREATE INDEX nuclei_findings_template_id_idx ON nuclei_findings (template_id);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS nuclei_findings;

    ALTER TABLE scan_schedules
      DROP COLUMN nuclei_profile,
      DROP COLUMN nuclei_tags,
      DROP COLUMN nuclei_profile_label;

    ALTER TABLE scan_requests
      DROP COLUMN nuclei_profile,
      DROP COLUMN nuclei_tags,
      DROP COLUMN nuclei_profile_label;

    DROP TABLE IF EXISTS nuclei_profiles;
  `);
};
