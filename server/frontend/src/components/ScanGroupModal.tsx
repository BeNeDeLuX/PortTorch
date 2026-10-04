import { useCallback, useEffect, useState } from "react";
import { api, Me, ScanGroupView } from "../api";
import { formatDateTime } from "../lib/formatDate";
import { IconPlay } from "./icons";
import Modal from "./Modal";

const POLL_INTERVAL_MS = 5000;

function shorten(spec: string, max = 80): string {
  return spec.length > max ? `${spec.slice(0, max)}...` : spec;
}

// A split scan as one thing: every scanner's share, what each is doing,
// and whether the scan as a whole is done - the question Scan History's
// per-job rows cannot answer on their own. Refreshes while any part is
// still queued or running, so it can be left open to watch the scan
// finish.
export default function ScanGroupModal({
  groupId,
  me,
  onClose,
  onChanged,
}: {
  groupId: string;
  me: Me;
  onClose: () => void;
  // Called after a resume, so the page behind can refresh too.
  onChanged?: () => void;
}) {
  const [group, setGroup] = useState<ScanGroupView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [resuming, setResuming] = useState(false);
  const canResume = me.role === "admin" || me.role === "operator";

  const load = useCallback(async () => {
    try {
      setGroup(await api.scanGroup(groupId));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load this scan.");
    }
  }, [groupId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (group?.status !== "running") return;
    const interval = setInterval(() => void load(), POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [group?.status, load]);

  async function resumeAll() {
    if (!group) return;
    if (!window.confirm(`Queue what the ${group.counts.resumable} unfinished part(s) of this scan never scanned, each on its own scanner with the original settings?`)) {
      return;
    }
    setResuming(true);
    setNotice(null);
    try {
      const { results } = await api.resumeScanGroup(group.id);
      const failed = results.filter((r) => !r.ok);
      setNotice(
        failed.length === 0
          ? { ok: true, text: `Queued the rest of ${results.length} part(s).` }
          : {
              ok: false,
              text: `Queued ${results.length - failed.length} of ${results.length}. ${failed.map((f) => `Part ${f.part}: ${f.error}`).join(" ")}`,
            }
      );
      await load();
      onChanged?.();
    } catch (err) {
      setNotice({ ok: false, text: err instanceof Error ? err.message : "Failed to resume" });
    } finally {
      setResuming(false);
    }
  }

  return (
    <Modal title="Split scan" onClose={onClose} wide>
      {error && <p className="error">{error}</p>}
      {!group && !error && <p>Loading...</p>}
      {group && (
        <>
          <div className="scan-group-summary">
            <strong title={group.targetSpec}>{shorten(group.targetSpec, 60)}</strong>
            <span className="host-meta">ports {shorten(group.portSpec, 40)}</span>
            <span className={`scan-status scan-status-${group.status}`}>{group.status}</span>
            <span className="host-meta">
              {group.counts.completed} of {group.parts} part{group.parts === 1 ? "" : "s"} completed
              {group.counts.running > 0 && `, ${group.counts.running} running`}
              {group.counts.queued > 0 && `, ${group.counts.queued} queued`}
              {group.counts.cancelled > 0 && `, ${group.counts.cancelled} cancelled`}
              {group.counts.failed > 0 && `, ${group.counts.failed} failed`}
            </span>
            <span className="host-meta">
              {formatDateTime(group.createdAt, me.preferences)}
              {group.requestedBy ? ` by ${group.requestedBy}` : ""}
              {group.masscanRateSplit ? " · rate divided between scanners" : ""}
            </span>
          </div>

          {notice && <p className={notice.ok ? "callout-success" : "callout-danger"}>{notice.text}</p>}

          <div className="table-scroll">
            <table className="scan-group-table">
              <thead>
                <tr>
                  <th>Part</th>
                  <th>Scanner</th>
                  <th>Share of the target</th>
                  <th>Status</th>
                  <th>Hosts</th>
                  <th>Open ports</th>
                </tr>
              </thead>
              <tbody>
                {group.partViews.map((p) => {
                  const latest = p.attempts[p.attempts.length - 1];
                  const first = p.attempts[0];
                  return (
                    <tr key={p.part}>
                      <td>
                        {p.part}/{group.parts}
                      </td>
                      <td>{p.scannerAgentName ?? "?"}</td>
                      <td className="spec-cell" title={first.targetSpec}>
                        {shorten(first.targetSpec)}
                        {p.attempts.length > 1 && (
                          <div className="host-meta" title={latest.targetSpec}>
                            resumed {p.attempts.length - 1}x - last: {shorten(latest.targetSpec, 50)}
                          </div>
                        )}
                        {p.resumable && latest.remainingTargetSpec && (
                          <div className="host-meta" title={latest.remainingTargetSpec}>
                            not finished: {shorten(latest.remainingTargetSpec, 50)}
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={`scan-status scan-status-${p.state}`}>{p.state}</span>
                      </td>
                      {/* Summed over every attempt at this part, since a
                          resume scans only what the one before missed. */}
                      <td>{p.attempts.some((a) => a.hostsScanned !== null) ? p.attempts.reduce((n, a) => n + (a.hostsScanned ?? 0), 0) : "-"}</td>
                      <td>{p.attempts.some((a) => a.openPortsFound !== null) ? p.attempts.reduce((n, a) => n + (a.openPortsFound ?? 0), 0) : "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {canResume && group.counts.resumable > 0 && (
            <div className="inline-actions">
              <button className="btn-icon-label" onClick={resumeAll} disabled={resuming}>
                <IconPlay /> {resuming ? "Queuing..." : `Resume ${group.counts.resumable} unfinished part${group.counts.resumable === 1 ? "" : "s"}`}
              </button>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
