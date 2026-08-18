/* eslint-disable */
exports.shorthands = undefined;

exports.up = (pgm) => {
  // Triage state for security findings - the ability to mark something a
  // false positive / accepted risk / fixed so it stops re-surfacing on the
  // Vulnerabilities and Web Findings pages after every single scan. There
  // was no such concept anywhere before this; the only workaround was a
  // free-text host comment, which nothing filters on.
  //
  // Its own table rather than a column on the finding itself, because
  // neither finding kind has a stable row to hang state off:
  //   - CVE matches aren't persisted at all - vulnerabilities/routes.ts
  //     derives them at query time by joining current_host_ports.cpes
  //     against cve_cache, so there is no row to update.
  //   - nuclei_findings rows ARE persisted, but a fresh row is inserted on
  //     every scan that re-observes the finding (one row per observation,
  //     deliberately - see the nuclei_profiles migration), so state stored
  //     there would be silently dropped on the next rescan.
  //
  // Identity therefore reuses whatever each kind already treats as its
  // identity elsewhere: (host_id, cve_id) for CVEs, and
  // (host_id, template_id, matched_at) for nuclei - the exact same triple
  // ingest/routes.ts already uses to decide whether a finding is "new"
  // enough to fire a webhook, and that nucleiFindings/routes.ts dedups on.
  //
  // Absence of a row means "open"/untriaged, the same "absence means the
  // default" idiom as scan_excludes.scanner_agent_id IS NULL or
  // api_tokens.expires_at IS NULL - so this table only ever holds the
  // deliberate exceptions, not a row per finding in the fleet.
  pgm.sql(`
    CREATE TABLE finding_triage (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      kind text NOT NULL CHECK (kind IN ('cve', 'nuclei')),
      host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      -- Exactly one identity shape is populated, enforced below - explicit
      -- nullable columns rather than one packed "key" string, so the
      -- database can actually check it and no caller has to parse a
      -- delimiter out of a URL (matched_at is a URL and could contain
      -- almost anything).
      cve_id text,
      template_id text,
      matched_at text,
      state text NOT NULL CHECK (state IN ('false_positive', 'accepted_risk', 'fixed')),
      note text,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT finding_triage_identity_check CHECK (
        (kind = 'cve' AND cve_id IS NOT NULL AND template_id IS NULL AND matched_at IS NULL)
        OR
        (kind = 'nuclei' AND cve_id IS NULL AND template_id IS NOT NULL AND matched_at IS NOT NULL)
      )
    );

    -- Two partial unique indexes rather than one plain UNIQUE across every
    -- column: Postgres treats each NULL as distinct, so a plain constraint
    -- would happily allow duplicate 'cve' rows (whose template_id/
    -- matched_at are both NULL). Same reasoning and same shape as
    -- scan_excludes_global_unique / scan_excludes_scanner_unique.
    CREATE UNIQUE INDEX finding_triage_cve_unique
      ON finding_triage (host_id, cve_id) WHERE kind = 'cve';
    CREATE UNIQUE INDEX finding_triage_nuclei_unique
      ON finding_triage (host_id, template_id, matched_at) WHERE kind = 'nuclei';

    CREATE INDEX finding_triage_host_id_idx ON finding_triage (host_id);
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TABLE IF EXISTS finding_triage;
  `);
};
