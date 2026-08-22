import { useState } from "react";
import { TRIAGE_LABEL, TriageState } from "../api";
import { IconCheck, IconX } from "./icons";

const STATES: TriageState[] = ["false_positive", "accepted_risk", "fixed"];

// Distinct from the placeholder's empty value - see apply() below.
const OPEN = "__open__";

// Shared by the Vulnerabilities and Web Findings pages. The triage state
// filter added alongside this made the gap obvious: you can now narrow
// precisely to forty open findings of the same template, and then had to
// work through them one dropdown at a time.
//
// Deliberately mirrors the Dashboard's own bulk toolbar rather than
// inventing a second pattern - it appears only once something is
// selected, states the count, and each page drives it by looping the
// existing single-finding endpoint with Promise.allSettled (no bulk API
// surface, so it inherits the same operator-level permission
// automatically). "Open" clears triage, exactly as the per-row control's
// own "Open" option does.
export default function BulkTriageBar({
  count,
  onApply,
  onClearSelection,
}: {
  count: number;
  onApply: (state: TriageState | null) => Promise<{ succeeded: number; failed: number }>;
  onClearSelection: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  if (count === 0) return null;

  // "" is the placeholder and OPEN is "clear triage" - two distinct
  // values, so neither can be mistaken for the other the way a shared
  // empty string would allow.
  async function apply(value: string) {
    if (value === "") return;
    setBusy(true);
    setResult(null);
    try {
      const { succeeded, failed } = await onApply(value === OPEN ? null : (value as TriageState));
      // Reported rather than assumed: with Promise.allSettled one finding
      // failing doesn't block the rest, so "applied to all of them" would
      // sometimes be a lie.
      setResult(failed === 0 ? `Updated ${succeeded}.` : `Updated ${succeeded}, ${failed} failed.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bulk-bar">
      <span>
        {count} selected
      </span>
      <label className="triage-filter">
        Set triage:{" "}
        <select defaultValue="" disabled={busy} onChange={(e) => { void apply(e.target.value); e.target.value = ""; }}>
          <option value="" disabled>
            Choose...
          </option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              {TRIAGE_LABEL[s]}
            </option>
          ))}
          <option value={OPEN}>Open (clear triage)</option>
        </select>
      </label>
      <button className="btn-icon-label" onClick={onClearSelection} disabled={busy}>
        <IconX /> Clear selection
      </button>
      {busy && <span className="host-meta">Working...</span>}
      {result && (
        <span className="host-meta">
          <IconCheck /> {result}
        </span>
      )}
    </div>
  );
}
