import { describe, expect, it } from "vitest";
import { TriageFilterable, matchesTriageFilter, triageCounts } from "./triageFilter";

const open: TriageFilterable = { triage_state: null, triage_expired: null };
const falsePositive: TriageFilterable = { triage_state: "false_positive", triage_expired: false };
const accepted: TriageFilterable = { triage_state: "accepted_risk", triage_expired: false };
const fixed: TriageFilterable = { triage_state: "fixed", triage_expired: false };
const expiredAccepted: TriageFilterable = { triage_state: "accepted_risk", triage_expired: true };

describe("matchesTriageFilter", () => {
  // This is exactly what the "Hide triaged findings" checkbox did when
  // checked, and it's the default both pages open on - so getting it
  // wrong silently changes what every analyst sees first.
  it("'needs a decision' is untriaged plus expired, not merely untriaged", () => {
    expect(matchesTriageFilter("needs_decision", open)).toBe(true);
    expect(matchesTriageFilter("needs_decision", expiredAccepted)).toBe(true);
    expect(matchesTriageFilter("needs_decision", falsePositive)).toBe(false);
    expect(matchesTriageFilter("needs_decision", accepted)).toBe(false);
    expect(matchesTriageFilter("needs_decision", fixed)).toBe(false);
  });

  it("'any triaged' is the complement of 'needs a decision'", () => {
    for (const row of [open, falsePositive, accepted, fixed, expiredAccepted]) {
      expect(matchesTriageFilter("any_triaged", row)).toBe(!matchesTriageFilter("needs_decision", row));
    }
  });

  // Someone filtering for "accepted risk" is asking what was decided, not
  // what is still in force - so expiry must not hide the row from its own
  // state's filter. "Review due" is the deliberate way to narrow to those.
  it("a specific state matches regardless of expiry", () => {
    expect(matchesTriageFilter("accepted_risk", accepted)).toBe(true);
    expect(matchesTriageFilter("accepted_risk", expiredAccepted)).toBe(true);
    expect(matchesTriageFilter("accepted_risk", falsePositive)).toBe(false);
    expect(matchesTriageFilter("accepted_risk", open)).toBe(false);
  });

  it("'review due' selects only expired decisions", () => {
    expect(matchesTriageFilter("review_due", expiredAccepted)).toBe(true);
    expect(matchesTriageFilter("review_due", accepted)).toBe(false);
    expect(matchesTriageFilter("review_due", open)).toBe(false);
  });

  it("'all' hides nothing", () => {
    for (const row of [open, falsePositive, accepted, fixed, expiredAccepted]) {
      expect(matchesTriageFilter("all", row)).toBe(true);
    }
  });

  // triage_expired arrives from the API as boolean | null (the SQL
  // expression yields NULL for an untriaged row), so the predicate has to
  // treat null as "not expired" rather than leaking it into a truthiness
  // bug the way a bare `row.triage_expired` return would.
  it("treats a null expired flag as not expired", () => {
    expect(matchesTriageFilter("review_due", { triage_state: "fixed", triage_expired: null })).toBe(false);
    expect(matchesTriageFilter("any_triaged", { triage_state: "fixed", triage_expired: null })).toBe(true);
  });
});

describe("triageCounts", () => {
  it("tallies each state and omits the ones with no rows", () => {
    expect(triageCounts([open, falsePositive, falsePositive, expiredAccepted])).toEqual([
      { label: "False positive", count: 2 },
      { label: "Accepted risk", count: 1 },
    ]);
  });

  it("counts an expired decision under the state it was actually set to", () => {
    expect(triageCounts([expiredAccepted])).toEqual([{ label: "Accepted risk", count: 1 }]);
  });

  it("is empty when nothing has been triaged", () => {
    expect(triageCounts([open, open])).toEqual([]);
  });
});
