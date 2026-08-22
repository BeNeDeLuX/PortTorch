import { TRIAGE_LABEL, TriageState } from "../api";

// Shared by the Vulnerabilities and Web Findings pages, which need the
// identical control and the identical predicate - same "one place so the
// two can't drift" reasoning as findingTriage/sqlFilters.ts on the server
// side, where the per-surface triage policy lives.
//
// This replaces what used to be a single "Hide triaged findings"
// checkbox on both pages. That could express only two of these seven
// states, and crucially not the one an analyst actually asks for: "show
// me what we already decided was a false positive" (or accepted, or
// fixed). Reviewing past decisions is a normal part of vulnerability
// management, and the checkbox made it impossible.
export type TriageFilter = "needs_decision" | "any_triaged" | TriageState | "review_due" | "all";

export const TRIAGE_FILTER_OPTIONS: { value: TriageFilter; label: string }[] = [
  { value: "needs_decision", label: "Needs a decision" },
  { value: "any_triaged", label: "Any triaged" },
  { value: "false_positive", label: TRIAGE_LABEL.false_positive },
  { value: "accepted_risk", label: TRIAGE_LABEL.accepted_risk },
  { value: "fixed", label: TRIAGE_LABEL.fixed },
  { value: "review_due", label: "Review due" },
  { value: "all", label: "All" },
];

// The two fields both finding kinds already carry - deliberately a
// structural type rather than a union of the two row types, so this stays
// usable for any future finding kind without being edited.
export interface TriageFilterable {
  triage_state: TriageState | null;
  triage_expired: boolean | null;
}

// "needs_decision" is the default on both pages and is exactly what the
// old checkbox did when checked: untriaged findings, plus ones whose
// decision has since expired and is therefore no longer being honored
// (see finding_triage.review_at). It is NOT the same as "untriaged".
//
// A specific state matches regardless of expiry - an expired
// accepted_risk was still *set* to accepted_risk, and someone filtering
// for it is asking what was decided, not what is currently in force.
// "review_due" is how you narrow to the expired ones on purpose.
export function matchesTriageFilter(filter: TriageFilter, row: TriageFilterable): boolean {
  switch (filter) {
    case "all":
      return true;
    case "needs_decision":
      return !row.triage_state || !!row.triage_expired;
    case "any_triaged":
      return !!row.triage_state && !row.triage_expired;
    case "review_due":
      return !!row.triage_expired;
    default:
      return row.triage_state === filter;
  }
}

// Per-state tallies for the summary line under the controls, so the
// states that exist at all are visible without cycling the filter through
// every option to find out which ones are empty.
export function triageCounts(rows: TriageFilterable[]): { label: string; count: number }[] {
  return (["false_positive", "accepted_risk", "fixed"] as TriageState[])
    .map((s) => ({ label: TRIAGE_LABEL[s], count: rows.filter((r) => r.triage_state === s).length }))
    .filter((entry) => entry.count > 0);
}
