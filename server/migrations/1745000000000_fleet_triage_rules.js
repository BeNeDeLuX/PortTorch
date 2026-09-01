/* eslint-disable */
exports.shorthands = undefined;

/**
 * Triage that applies to a finding everywhere, not host by host.
 *
 * finding_triage.host_id is NOT NULL, so a CVE that is a false positive
 * across the whole fleet - the usual cause being a CPE that matches a
 * product the host does not actually run - has to be dismissed once per
 * affected host. On 200 hosts that is 200 decisions, and the next host
 * discovered running the same software starts the argument again.
 *
 * A separate table rather than a nullable host_id on finding_triage:
 * "this CVE never applies to us" and "we accepted this risk on this one
 * host" are different statements, made by different people for different
 * reasons, and mixing them into one table would mean every existing query
 * and both partial unique indexes had to learn the difference. Per-host
 * triage keeps working exactly as it did.
 *
 * Precedence is specific-over-general: a per-host decision wins over a
 * fleet rule, because someone looked at that host and decided. This is
 * the opposite of scan_excludes' global/per-scanner union, and
 * deliberately so - there the two combine because both are restrictions,
 * here they can genuinely disagree and one has to win.
 */
exports.up = async (pgm) => {
  await pgm.db.query(`
    CREATE TABLE finding_triage_rules (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      kind text NOT NULL CHECK (kind IN ('cve', 'nuclei')),
      cve_id text,
      template_id text,
      state text NOT NULL CHECK (state IN ('false_positive', 'accepted_risk', 'fixed')),
      note text,
      created_by text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      -- Exactly one identifier, matching its kind - the same shape
      -- finding_triage's own constraint enforces.
      CHECK (
        (kind = 'cve' AND cve_id IS NOT NULL AND template_id IS NULL) OR
        (kind = 'nuclei' AND template_id IS NOT NULL AND cve_id IS NULL)
      )
    );

    -- One rule per finding identity. Partial indexes rather than a plain
    -- UNIQUE for the same reason as scan_excludes: NULLs are all distinct
    -- to a plain unique constraint, so it would never catch a duplicate.
    CREATE UNIQUE INDEX finding_triage_rules_cve_unique
      ON finding_triage_rules (cve_id) WHERE kind = 'cve';
    CREATE UNIQUE INDEX finding_triage_rules_template_unique
      ON finding_triage_rules (template_id) WHERE kind = 'nuclei';
  `);
};

exports.down = async (pgm) => {
  await pgm.db.query(`DROP TABLE IF EXISTS finding_triage_rules`);
};
