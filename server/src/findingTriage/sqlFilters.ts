import { sql } from "kysely";

// Which triage states suppress a CVE where, in one place, because the
// answer genuinely differs per surface and letting each call site decide
// for itself is how the four of them would quietly drift apart.
//
// "Not a live risk" - the finding either was never real (false_positive)
// or no longer is (fixed). Excluded from anything that quantifies current
// exposure: the host list's risk indicator (cve_count / max_cvss_score /
// has_kev). accepted_risk is deliberately NOT here: an accepted risk is
// still a real, still-present exposure - someone decided to live with it,
// which doesn't make the host less exposed, and silently dropping it from
// the risk number would misrepresent the fleet.
export const NOT_A_LIVE_RISK_STATES = ["false_positive", "fixed"] as const;

// Any triage state at all - a human has already made a call on this
// finding. Used for alerting (EPSS/KEV webhooks): re-alerting on
// something explicitly triaged, including an accepted risk, is exactly
// the alert fatigue triage exists to prevent. Note this is deliberately
// broader than the risk-indicator set above.
export const ANY_TRIAGE_STATE = ["false_positive", "accepted_risk", "fixed"] as const;

/**
 * A `NOT EXISTS (...)` predicate excluding CVEs triaged into any of
 * `states` for that host. Takes the caller's own column expressions as
 * raw SQL because the four call sites use different table aliases
 * (chp/chp2/h) inside otherwise unrelated raw queries.
 *
 * Deliberately a predicate rather than a join: these are all correlated
 * subqueries or aggregates already, and a join would risk changing row
 * multiplicity in queries that count distinct CVEs.
 */
export function cveNotTriaged(hostIdExpr: string, cveIdExpr: string, states: readonly string[]) {
  return sql`NOT EXISTS (
    SELECT 1 FROM finding_triage ft
    WHERE ft.kind = 'cve'
      AND ft.host_id = ${sql.raw(hostIdExpr)}
      AND ft.cve_id = ${sql.raw(cveIdExpr)}
      AND ft.state = ANY(${[...states]})
      -- An expired decision stops being honored everywhere at once: it no
      -- longer suppresses the finding here, exactly as if the row weren't
      -- there. The row itself is kept (see the review_at migration) - who
      -- decided what and when is worth more than the space it costs.
      AND (ft.review_at IS NULL OR ft.review_at > now())
  )`;
}
