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
// one click matters more than confirming it. The optional note is a
// separate, opt-in step for the same reason.
export default function TriageControl({
  target,
  state,
  note,
  canEdit,
  onChanged,
}: {
  target: TriageTarget;
  state: TriageState | null;
  note: string | null;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!canEdit) {
    return state ? <span className={`triage-badge triage-${state}`}>{TRIAGE_LABEL[state]}</span> : <span className="host-meta">-</span>;
  }

  async function apply(next: string) {
    setBusy(true);
    setError(null);
    try {
      if (next === "") {
        // Only meaningful if something was actually set - the server 404s
        // on clearing an untriaged finding, which would be a confusing
        // error for what is visually a no-op.
        if (state) await api.clearFindingTriage(target);
      } else {
        await api.setFindingTriage(target, next as TriageState, note ?? undefined);
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
        className={state ? `triage-select triage-${state}` : "triage-select"}
        value={state ?? ""}
        disabled={busy}
        onChange={(e) => apply(e.target.value)}
        title={note ?? undefined}
      >
        <option value="">Open</option>
        {STATES.map((s) => (
          <option key={s} value={s}>
            {TRIAGE_LABEL[s]}
          </option>
        ))}
      </select>
      {note && (
        <span className="triage-note" title={note}>
          {note}
        </span>
      )}
      {error && <span className="error">{error}</span>}
    </div>
  );
}
