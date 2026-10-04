import { FormEvent, useEffect, useState } from "react";
import { api, Me, NetworkBaseline, NetworkBaselineSummary, ScannerAgent, SubnetChangesResult } from "../api";
import { IconCheck, IconPlus, IconSearch, IconTrash, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { ChangesReport } from "../components/SubnetChanges";
import { formatDateTime } from "../lib/formatDate";

const ALL_SCANNERS = "";

// "This network looked right at this moment", and everything that changed
// since. Deviations are the Subnets Changes comparison from the approval
// to now; new hosts and opened or closed ports raise a baseline.deviation
// alert once each. Approving again accepts them all.
export default function Baselines({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const canEdit = me.role === "admin" || me.role === "operator";
  const [baselines, setBaselines] = useState<NetworkBaselineSummary[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [network, setNetwork] = useState("");
  const [scannerAgentId, setScannerAgentId] = useState(ALL_SCANNERS);
  const [note, setNote] = useState("");
  const [detail, setDetail] = useState<{ baseline: NetworkBaseline; changes: SubnetChangesResult } | null>(null);

  async function load() {
    setLoading(true);
    try {
      setBaselines(await api.baselines());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load baselines");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    api.agents().then((a) => setAgents(a.filter((x) => !x.revoked_at)));
  }, []);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.createBaseline(network.trim(), scannerAgentId || null, note.trim() || null);
      setNetwork("");
      setNote("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the baseline");
    }
  }

  async function openDetail(b: NetworkBaselineSummary) {
    setError(null);
    try {
      setDetail(await api.baseline(b.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the deviations");
    }
  }

  async function handleApprove(b: NetworkBaselineSummary | NetworkBaseline) {
    if (
      !window.confirm(
        `Accept the current state of ${b.network} as its baseline? Every deviation listed now becomes part of what is expected, and stops being reported.`
      )
    ) {
      return;
    }
    await api.approveBaseline(b.id);
    setDetail(null);
    await load();
  }

  async function handleDelete(b: NetworkBaselineSummary) {
    if (!window.confirm(`Delete the baseline for ${b.network}? Deviations from it will no longer be reported.`)) return;
    await api.deleteBaseline(b.id);
    if (detail?.baseline.id === b.id) setDetail(null);
    await load();
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Baselines</h2>
      <p className="host-meta">
        Approve a network's current state as expected, and see what has changed since: new hosts, and ports that opened or
        closed. Each new deviation is reported once through the <code>baseline.deviation</code> alert. Approving again
        accepts everything that changed. Hosts not seen since the approval are listed but do not alert, since a range nobody
        scanned would otherwise report every host in it.
      </p>

      {error && <p className="callout-danger">{error}</p>}

      {canEdit && (
        <form className="schedule-form" onSubmit={handleCreate}>
          <label>
            Network
            <input placeholder="10.46.0.0/16 or 10.46" value={network} onChange={(e) => setNetwork(e.target.value)} />
          </label>
          <label>
            Scope
            <select value={scannerAgentId} onChange={(e) => setScannerAgentId(e.target.value)}>
              <option value={ALL_SCANNERS}>All scanners</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Note
            <input placeholder="What this network is" value={note} onChange={(e) => setNote(e.target.value)} />
          </label>
          <button type="submit" className="btn-icon-label" disabled={!network.trim()}>
            <IconPlus /> Approve current state
          </button>
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : baselines.length === 0 ? (
        <p className="empty">No baselines yet.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Scope</th>
                <th>Approved</th>
                <th>Since then</th>
                <th>Scans since</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {baselines.map((b) => (
                <tr key={b.id}>
                  <td>
                    <strong>{b.network}</strong>
                    {b.note && <div className="host-meta">{b.note}</div>}
                  </td>
                  <td>{b.scanner_agent_name ?? "All scanners"}</td>
                  <td>
                    {formatDateTime(b.approved_at, me.preferences)}
                    {b.approved_by && <div className="host-meta">by {b.approved_by}</div>}
                  </td>
                  <td>
                    <DeviationBadges b={b} />
                  </td>
                  <td>{b.scansSinceApproval}</td>
                  <td>
                    <div className="inline-actions">
                      <button className="btn-icon-label" onClick={() => openDetail(b)}>
                        <IconSearch /> Details
                      </button>
                      {canEdit && b.deviations.alerting + unseenCounts(b) > 0 && (
                        <button className="btn-icon-label" onClick={() => handleApprove(b)}>
                          <IconCheck /> Accept changes
                        </button>
                      )}
                      {canEdit && (
                        <button className="btn-icon-label" onClick={() => handleDelete(b)}>
                          <IconTrash /> Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <section className="baseline-detail">
          <h3>
            {detail.baseline.network}
            <span className="host-meta">
              {" "}
              · changes since {formatDateTime(detail.baseline.approved_at, me.preferences)}
              {detail.baseline.scanner_agent_name ? ` · ${detail.baseline.scanner_agent_name}` : ""}
            </span>
          </h3>
          <div className="inline-actions">
            {canEdit && (
              <button className="btn-icon-label" onClick={() => handleApprove(detail.baseline)}>
                <IconCheck /> Accept changes
              </button>
            )}
            <button className="btn-icon-label" onClick={() => setDetail(null)}>
              <IconX /> Close
            </button>
          </div>
          <ChangesReport result={detail.changes} me={me} />
        </section>
      )}
    </div>
  );
}

// "Not seen" only means something once a scan has run since the approval:
// right after approving, every host is "not seen since" by definition.
function unseenCounts(b: NetworkBaselineSummary): number {
  return b.scansSinceApproval > 0 ? b.deviations.unseenHosts : 0;
}

function DeviationBadges({ b }: { b: NetworkBaselineSummary }) {
  const d = b.deviations;
  if (d.alerting === 0 && unseenCounts(b) === 0) {
    return b.scansSinceApproval === 0 ? (
      <span className="host-meta">no scan since approval</span>
    ) : (
      <span className="baseline-ok">matches</span>
    );
  }
  const plus = d.truncated ? "+" : "";
  return (
    <span className="baseline-deviations">
      {d.newHosts > 0 && <span className="stale-badge">{d.newHosts}{plus} new host{d.newHosts === 1 ? "" : "s"}</span>}
      {d.openedPorts > 0 && <span className="stale-badge">{d.openedPorts}{plus} opened</span>}
      {d.closedPorts > 0 && <span className="stale-badge">{d.closedPorts}{plus} closed</span>}
      {unseenCounts(b) > 0 && (
        <span className="host-meta" title="Known at approval, not reported by any scan since - gone, or not scanned">
          {d.unseenHosts}{plus} not seen
        </span>
      )}
    </span>
  );
}
