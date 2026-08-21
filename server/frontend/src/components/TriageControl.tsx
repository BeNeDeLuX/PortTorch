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
  canEdit,
  onChanged,
}: {
  target: TriageTarget;
  state: TriageState | null;
  note: string | null;
  reviewAt: string | null;
  expired: boolean | null;
  canEdit: boolean;
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
      </span>
    );
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
