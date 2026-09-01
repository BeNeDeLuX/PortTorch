import { useState } from "react";
import { api, TRIAGE_LABEL, TriageState, TriageTarget } from "../api";

const STATES: TriageState[] = ["false_positive", "accepted_risk", "fixed"];

// Shared by the Vulnerabilities and Web Findings pages - both need the
// exact same "mark this finding so it stops competing for attention"
// control, and the two finding kinds differ only in how they're
// identified (TriageTarget), not in how they're triaged.
//
// Deliberately a plain <select> rather than a modal: triaging is a
// high-frequency, low-stakes action (it never deletes scan data - the
// finding is untouched, only its display state changes, and it's
// reversible from the same control by picking "Open" again), so making it
// one click matters more than confirming it.
//
// The review date is a second, optional step for the same reason - it
// only appears once something is actually triaged, since it's meaningless
// for an open finding.
export default function TriageControl({
  target,
  state,
  note,
  reviewAt,
  expired,
  fromRule,
  canEdit,
  canSetRule = false,
  onChanged,
}: {
  target: TriageTarget;
  state: TriageState | null;
  note: string | null;
  reviewAt: string | null;
  expired: boolean | null;
  // The state came from a fleet-wide rule, not from a decision about this
  // host - shown differently, since otherwise it looks like somebody
  // examined this host and never took it back.
  fromRule?: boolean | null;
  canEdit: boolean;
  // Fleet rules are admin-only: they silence a finding on every host,
  // including ones nobody has looked at and ones that don't exist yet.
  canSetRule?: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // <input type="date"> wants YYYY-MM-DD; the API carries a full ISO
  // timestamp.
  const reviewDateValue = reviewAt ? reviewAt.slice(0, 10) : "";

  if (!canEdit) {
    if (!state) return <span className="host-meta">-</span>;
    return (
      <span className={`triage-badge triage-${expired ? "expired" : state}`}>
        {TRIAGE_LABEL[state]}
        {expired ? " · review due" : ""}
        {fromRule ? " · fleet-wide" : ""}
      </span>
    );
  }

  async function applyRule() {
    if (
      !window.confirm(
        "Dismiss this finding on every host, including hosts nobody has looked at and hosts discovered later? " +
          "A decision made on an individual host still overrides this."
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.setFindingTriageRule(target, (state ?? "false_positive") as TriageState, note ?? undefined);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setBusy(false);
    }
  }

  async function apply(nextState: string, nextReviewAt: string | null | undefined) {
    setBusy(true);
    setError(null);
    try {
      if (nextState === "") {
        // Only meaningful if something was actually set - the server 404s
        // on clearing an untriaged finding, which would be a confusing
        // error for what is visually a no-op.
        if (state) await api.clearFindingTriage(target);
      } else {
        await api.setFindingTriage(target, nextState as TriageState, note ?? undefined, nextReviewAt);
      }
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="triage-control">
      <select
        className={state ? `triage-select triage-${expired ? "expired" : state}` : "triage-select"}
        value={state ?? ""}
        disabled={busy}
        onChange={(e) => apply(e.target.value, reviewAt)}
        title={note ?? undefined}
      >
        <option value="">Open</option>
        {STATES.map((s) => (
          <option key={s} value={s}>
            {TRIAGE_LABEL[s]}
          </option>
        ))}
      </select>

      {state && (
        <input
          type="date"
          className="triage-review-date"
          value={reviewDateValue}
          disabled={busy}
          // Sent as end-of-day UTC so a date picked as "review on the 30th"
          // stays honored through that whole day rather than lapsing at
          // 00:00 on it.
          onChange={(e) => apply(state, e.target.value ? `${e.target.value}T23:59:59.000Z` : null)}
          title={
            reviewAt
              ? `This decision stops applying after ${reviewDateValue}, and the finding comes back`
              : "Optional: a date after which this decision expires and the finding resurfaces"
          }
        />
      )}

      {fromRule && (
        <span className="triage-badge triage-rule" title="Dismissed fleet-wide, not on this host specifically">
          fleet-wide
        </span>
      )}
      {canSetRule && state && !fromRule && (
        <button
          type="button"
          className="link-button"
          disabled={busy}
          title="Apply this decision to this finding on every host"
          onClick={applyRule}
        >
          apply fleet-wide
        </button>
      )}
      {expired && <span className="triage-badge triage-expired">review due</span>}
      {note && (
        <span className="triage-note" title={note}>
          {note}
        </span>
      )}
      {error && <span className="error">{error}</span>}
    </div>
  );
}
