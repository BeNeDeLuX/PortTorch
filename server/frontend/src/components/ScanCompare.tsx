import { useMemo, useState } from "react";
import { HostPortObservation, UserPreferences } from "../api";
import { diffScans, scanRuns } from "../lib/scanDiff";
import { formatDateTime } from "../lib/formatDate";

// Comparing two of this host's own scans. The Digest answers "what
// changed across the fleet in a window" and the timeline below answers
// "what did each scan see"; neither answers "what changed on this host
// between these two scans", which is the question after an incident or a
// change window.
//
// Entirely derived from the history already on the page - no request, no
// endpoint, so the comparison can never disagree with the timeline it
// sits next to.
export default function ScanCompare({
  history,
  preferences,
}: {
  history: HostPortObservation[];
  preferences: UserPreferences;
}) {
  const runs = useMemo(() => scanRuns(history), [history]);
  // Defaults to the two most recent, which is the comparison people want
  // nine times out of ten - and makes the feature useful without any
  // interaction at all.
  const [afterId, setAfterId] = useState(runs[0]?.scanJobId ?? "");
  const [beforeId, setBeforeId] = useState(runs[1]?.scanJobId ?? "");
  const [showUnchanged, setShowUnchanged] = useState(false);

  const changes = useMemo(
    () => (beforeId && afterId ? diffScans(history, beforeId, afterId) : []),
    [history, beforeId, afterId]
  );

  if (runs.length < 2) {
    return (
      <p className="empty">
        Only one scan has recorded anything for this host so far - a comparison needs two.
      </p>
    );
  }

  const visible = showUnchanged ? changes : changes.filter((c) => c.kind !== "unchanged");
  const changed = changes.filter((c) => c.kind !== "unchanged");

  const label = (id: string) => {
    const run = runs.find((r) => r.scanJobId === id);
    if (!run) return id.slice(0, 8);
    return `${formatDateTime(run.observedAt, preferences)} · ${run.portCount} port(s)${
      run.scannerAgentName ? ` · ${run.scannerAgentName}` : ""
    }`;
  };

  return (
    <>
      <div className="list-controls">
        <label className="hide-empty-toggle">
          Earlier scan
          <select value={beforeId} onChange={(e) => setBeforeId(e.target.value)}>
            {runs.map((r) => (
              <option key={r.scanJobId} value={r.scanJobId}>
                {label(r.scanJobId)}
              </option>
            ))}
          </select>
        </label>
        <label className="hide-empty-toggle">
          Later scan
          <select value={afterId} onChange={(e) => setAfterId(e.target.value)}>
            {runs.map((r) => (
              <option key={r.scanJobId} value={r.scanJobId}>
                {label(r.scanJobId)}
              </option>
            ))}
          </select>
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={showUnchanged} onChange={(e) => setShowUnchanged(e.target.checked)} />
          Also show ports that stayed the same
        </label>
      </div>

      {beforeId === afterId ? (
        <p className="empty">Pick two different scans to compare.</p>
      ) : changed.length === 0 ? (
        <p className="empty">Nothing changed between these two scans.</p>
      ) : (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Change</th>
                  <th>Earlier</th>
                  <th>Later</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((c) => (
                  <tr key={`${c.port}/${c.protocol}`}>
                    <td>
                      {c.port}/{c.protocol}
                    </td>
                    <td>
                      {c.kind === "opened" && <span className="expiry-label expiry-expired">opened</span>}
                      {c.kind === "closed" && <span className="chip-inline">closed</span>}
                      {c.kind === "changed" && <span className="expiry-label expiry-soon">changed</span>}
                      {c.kind === "unchanged" && <span className="empty">unchanged</span>}
                      {c.details.length > 0 && <div className="host-meta">{c.details.join(", ")}</div>}
                    </td>
                    <td>{c.before?.state === "open" ? c.before.service_name ?? "open" : <span className="empty">-</span>}</td>
                    <td>{c.after?.state === "open" ? c.after.service_name ?? "open" : <span className="empty">-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="empty">
            "Closed" means the later scan did not report the port as open - which is a genuine close, or a port that
            scan's own port spec never covered. masscan only ever reports what it finds open, so the two cannot be told
            apart from here; check the two scans' port specs on Scan History if it matters.
          </p>
        </>
      )}
    </>
  );
}
