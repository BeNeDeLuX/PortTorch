import { FormEvent, useEffect, useState } from "react";
import { ActiveScanJob, api, Me, QueuedScanRequest, ScannerAgent } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import { formatDateTime } from "../lib/formatDate";
import { elapsedLabel } from "../lib/elapsed";

type SortKey = "name" | "last_seen_at" | "last_seen_ip" | "version" | "current_scan" | "created_at";
type SortDirection = "asc" | "desc";

type QueueSortKey = "target_spec" | "port_spec" | "scanner_agent_name" | "host" | "requested_by" | "created_at";

function compareQueued(a: QueuedScanRequest, b: QueuedScanRequest, key: QueueSortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "target_spec":
      return sign * a.target_spec.localeCompare(b.target_spec);
    case "port_spec":
      return sign * a.port_spec.localeCompare(b.port_spec);
    case "scanner_agent_name":
      return sign * (a.scanner_agent_name ?? "").localeCompare(b.scanner_agent_name ?? "");
    case "host":
      return sign * (a.host_hostname ?? a.host_ip ?? "").localeCompare(b.host_hostname ?? b.host_ip ?? "");
    case "requested_by":
      return sign * (a.requested_by ?? "").localeCompare(b.requested_by ?? "");
    case "created_at":
      return sign * (new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    default:
      return 0;
  }
}

// activeJobByAgent is only used by "current_scan" - passed in rather than
// looked up globally since ScannerAgent itself doesn't carry it (it comes
// from the separate /api/scan-jobs/active poll).
function compareAgents(
  a: ScannerAgent,
  b: ScannerAgent,
  key: SortKey,
  direction: SortDirection,
  activeJobByAgent: Map<string, ActiveScanJob>
): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "name":
      return sign * a.name.localeCompare(b.name);
    case "last_seen_at": {
      const at = a.last_seen_at ? new Date(a.last_seen_at).getTime() : -Infinity;
      const bt = b.last_seen_at ? new Date(b.last_seen_at).getTime() : -Infinity;
      return sign * (at - bt);
    }
    case "last_seen_ip":
      return sign * (a.last_seen_ip ?? "").localeCompare(b.last_seen_ip ?? "");
    case "version":
      return sign * (a.version ?? "").localeCompare(b.version ?? "");
    case "current_scan": {
      // Idle agents sort after every running one (Infinity sentinel,
      // same convention as last_seen_at's -Infinity for "never"); among
      // running agents, oldest-started (most likely stuck) first.
      const aJob = activeJobByAgent.get(a.id);
      const bJob = activeJobByAgent.get(b.id);
      const at = aJob ? new Date(aJob.started_at).getTime() : Infinity;
      const bt = bJob ? new Date(bJob.started_at).getTime() : Infinity;
      return sign * (at - bt);
    }
    case "created_at":
      return sign * (new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    default:
      return 0;
  }
}

export default function ScannerAgents({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === "admin";
  const canEdit = me.role === "admin" || me.role === "operator";
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [name, setName] = useState("");
  const [newKey, setNewKey] = useState<{ name: string; apiKey: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [queueSortKey, setQueueSortKey] = useState<QueueSortKey>("created_at");
  const [queueSortDirection, setQueueSortDirection] = useState<SortDirection>("asc");
  const [activeScanJobs, setActiveScanJobs] = useState<ActiveScanJob[]>([]);
  const [scanQueue, setScanQueue] = useState<QueuedScanRequest[]>([]);
  const [queueScannerFilterIds, setQueueScannerFilterIds] = useState<string[]>([]);
  // Forces a re-render every few seconds so elapsedLabel's "running for
  // Xm Ys" stays live between polls, not just when the job list changes.
  const [, setClockTick] = useState(0);

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("asc");
    }
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  function setQueueSort(key: QueueSortKey) {
    if (queueSortKey === key) {
      setQueueSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setQueueSortKey(key);
      setQueueSortDirection("asc");
    }
  }

  function queueSortIndicator(key: QueueSortKey): string {
    if (queueSortKey !== key) return "";
    return queueSortDirection === "asc" ? " ▲" : " ▼";
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    loadActiveScanJobs();
    loadScanQueue();
    const jobsInterval = setInterval(loadActiveScanJobs, 5000);
    const queueInterval = setInterval(loadScanQueue, 5000);
    const clockInterval = setInterval(() => setClockTick((t) => t + 1), 1000);
    return () => {
      clearInterval(jobsInterval);
      clearInterval(queueInterval);
      clearInterval(clockInterval);
    };
  }, []);

  async function load() {
    setLoading(true);
    try {
      setAgents(await api.agents());
    } finally {
      setLoading(false);
    }
  }

  async function loadActiveScanJobs() {
    try {
      setActiveScanJobs(await api.activeScanJobs());
    } catch {
      setActiveScanJobs([]);
    }
  }

  async function loadScanQueue() {
    try {
      setScanQueue(await api.scanQueue());
    } catch {
      setScanQueue([]);
    }
  }

  async function handleDismissScanJob(id: string) {
    if (!window.confirm("Dismiss this stale scan? The scanner isn't notified - if it's actually still running, its next update is simply ignored.")) {
      return;
    }
    await api.dismissScanJob(id);
    await loadActiveScanJobs();
  }

  async function handleCancelScanJob(id: string) {
    if (!window.confirm("Stop this scan? The scanner will notice on its next check and abort.")) {
      return;
    }
    await api.cancelScanJob(id);
    await loadActiveScanJobs();
  }

  async function handleCancelQueuedScanRequest(id: string) {
    if (!window.confirm("Cancel this queued scan request? It hasn't started yet - the scanner will simply never pick it up.")) {
      return;
    }
    await api.cancelQueuedScanRequest(id);
    await loadScanQueue();
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const created = await api.createAgent(name.trim());
    setNewKey({ name: created.name, apiKey: created.apiKey });
    setName("");
    await load();
  }

  async function handleRevoke(a: ScannerAgent) {
    if (!window.confirm(`Revoke "${a.name}"? It will no longer be able to authenticate, but its scan history stays intact.`)) {
      return;
    }
    await api.revokeAgent(a.id);
    await load();
  }

  async function handleDelete(a: ScannerAgent) {
    if (
      !window.confirm(
        `Permanently delete "${a.name}"? Its scan history (jobs, screenshots, etc.) is kept, but any recurring schedules or excludes scoped to it are removed. This can't be undone.`
      )
    ) {
      return;
    }
    await api.deleteAgent(a.id);
    await load();
  }

  const activeJobByAgent = new Map(activeScanJobs.map((j) => [j.scanner_agent_id, j]));

  const scanning = agents.filter((a) => !a.revoked_at && activeJobByAgent.has(a.id));
  const idle = agents.filter((a) => !a.revoked_at && !activeJobByAgent.has(a.id));
  const revoked = agents.filter((a) => a.revoked_at);

  function sortedGroup(group: ScannerAgent[]): ScannerAgent[] {
    return [...group].sort((a, b) => compareAgents(a, b, sortKey, sortDirection, activeJobByAgent));
  }

  const filteredQueue =
    queueScannerFilterIds.length === 0
      ? scanQueue
      : scanQueue.filter((q) => q.scanner_agent_id !== null && queueScannerFilterIds.includes(q.scanner_agent_id));
  const sortedQueue = [...filteredQueue].sort((a, b) => compareQueued(a, b, queueSortKey, queueSortDirection));

  const sharedHeaders = (
    <>
      <th onClick={() => setSort("name")}>Name{sortIndicator("name")}</th>
      <th onClick={() => setSort("last_seen_at")}>Last seen{sortIndicator("last_seen_at")}</th>
      <th onClick={() => setSort("last_seen_ip")}>Last seen from{sortIndicator("last_seen_ip")}</th>
      <th onClick={() => setSort("version")}>Version{sortIndicator("version")}</th>
    </>
  );

  function sharedCells(a: ScannerAgent) {
    return (
      <>
        <td>{a.name}</td>
        <td>{a.last_seen_at ? formatDateTime(a.last_seen_at, me.preferences) : "never"}</td>
        <td>{a.last_seen_ip ?? "-"}</td>
        <td>{a.version ?? "-"}</td>
      </>
    );
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Scanner Agents</h2>

      {newKey && (
        <div className="callout">
          <strong>API key for "{newKey.name}"</strong> (shown only now — add it to the
          scanner's config.yaml):
          <pre className="key-reveal">{newKey.apiKey}</pre>
          <button onClick={() => setNewKey(null)}>Got it</button>
        </div>
      )}

      {isAdmin && (
        <form className="inline-form" onSubmit={handleCreate}>
          <input placeholder="Scanner name, e.g. scanner-office-1" value={name} onChange={(e) => setName(e.target.value)} />
          <button type="submit">Create</button>
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : agents.length === 0 ? (
        <p className="empty">No scanner agents created yet.</p>
      ) : (
        <>
          <h3>Scanning ({scanning.length})</h3>
          {scanning.length === 0 ? (
            <p className="empty">No scanner currently running a scan.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>
                  {sharedHeaders}
                  <th onClick={() => setSort("current_scan")}>Current scan{sortIndicator("current_scan")}</th>
                  <th onClick={() => setSort("created_at")}>Created{sortIndicator("created_at")}</th>
                  {canEdit && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {sortedGroup(scanning).map((a) => {
                  const activeJob = activeJobByAgent.get(a.id);
                  return (
                    <tr key={a.id}>
                      {sharedCells(a)}
                      <td>
                        {activeJob && (
                          <>
                            {activeJob.target_spec} <span className="host-meta">(ports {activeJob.port_spec})</span>
                            <div className="host-meta">
                              running {elapsedLabel(activeJob.started_at)}
                              {activeJob.is_stale && (
                                <span
                                  className="stale-badge"
                                  title="No update in a while - this scanner may be offline or have died mid-scan"
                                >
                                  stale
                                </span>
                              )}
                            </div>
                            {activeJob.applicable_excludes && activeJob.applicable_excludes.length > 0 && (
                              <div className="host-meta">
                                Excludes: {activeJob.applicable_excludes.map((e) => `${e.kind}: ${e.value}`).join(", ")}
                              </div>
                            )}
                          </>
                        )}
                      </td>
                      <td>{formatDateTime(a.created_at, me.preferences)}</td>
                      {canEdit && (
                        <td>
                          <div className="actions-cell">
                            {activeJob?.is_stale && (
                              <button className="link-button" onClick={() => handleDismissScanJob(activeJob.id)}>
                                dismiss
                              </button>
                            )}
                            {activeJob?.cancellable && (
                              <button
                                onClick={() => handleCancelScanJob(activeJob.id)}
                                disabled={activeJob.cancel_requested}
                              >
                                {activeJob.cancel_requested ? "Stopping..." : "Stop"}
                              </button>
                            )}
                            {isAdmin && <button onClick={() => handleRevoke(a)}>Revoke</button>}
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          <div className="list-controls">
            <h3>Queued ({filteredQueue.length})</h3>
            {scanQueue.length > 0 && (
              <label className="hide-empty-toggle">
                Scanner
                <ScannerMultiSelect
                  agents={agents.filter((a) => !a.revoked_at)}
                  selectedIds={queueScannerFilterIds}
                  onChange={setQueueScannerFilterIds}
                  align="right"
                />
              </label>
            )}
          </div>
          {scanQueue.length === 0 ? (
            <p className="empty">No scan requests waiting - a scanner busy with another job would show its queued rescans/schedules here.</p>
          ) : filteredQueue.length === 0 ? (
            <p className="empty">No queued scan requests match the selected scanner(s).</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>
                  <th onClick={() => setQueueSort("target_spec")}>Target{queueSortIndicator("target_spec")}</th>
                  <th onClick={() => setQueueSort("port_spec")}>Ports{queueSortIndicator("port_spec")}</th>
                  <th onClick={() => setQueueSort("scanner_agent_name")}>Scanner{queueSortIndicator("scanner_agent_name")}</th>
                  <th onClick={() => setQueueSort("host")}>Host{queueSortIndicator("host")}</th>
                  <th onClick={() => setQueueSort("requested_by")}>Requested by{queueSortIndicator("requested_by")}</th>
                  <th onClick={() => setQueueSort("created_at")}>Queued since{queueSortIndicator("created_at")}</th>
                  {canEdit && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {sortedQueue.map((q) => (
                  <tr key={q.id}>
                    <td>{q.target_spec}</td>
                    <td>{q.port_spec}</td>
                    <td>{q.scanner_agent_name ?? "-"}</td>
                    <td>{q.host_hostname ?? q.host_ip ?? "-"}</td>
                    <td>{q.requested_by ?? "-"}</td>
                    <td>
                      {formatDateTime(q.created_at, me.preferences)}{" "}
                      <span className="host-meta">(waiting {elapsedLabel(q.created_at)})</span>
                    </td>
                    {canEdit && (
                      <td>
                        <div className="actions-cell">
                          <button onClick={() => handleCancelQueuedScanRequest(q.id)}>Cancel</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h3>Idle ({idle.length})</h3>
          {idle.length === 0 ? (
            <p className="empty">No idle scanner agents.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>
                  {sharedHeaders}
                  <th onClick={() => setSort("created_at")}>Created{sortIndicator("created_at")}</th>
                  {isAdmin && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {sortedGroup(idle).map((a) => (
                  <tr key={a.id}>
                    {sharedCells(a)}
                    <td>{formatDateTime(a.created_at, me.preferences)}</td>
                    {isAdmin && (
                      <td>
                        <div className="actions-cell">
                          <button onClick={() => handleRevoke(a)}>Revoke</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h3>Revoked ({revoked.length})</h3>
          {revoked.length === 0 ? (
            <p className="empty">No revoked scanner agents.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>
                  {sharedHeaders}
                  <th onClick={() => setSort("created_at")}>Created{sortIndicator("created_at")}</th>
                  <th>Revoked</th>
                  {isAdmin && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {sortedGroup(revoked).map((a) => (
                  <tr key={a.id}>
                    {sharedCells(a)}
                    <td>{formatDateTime(a.created_at, me.preferences)}</td>
                    <td>{a.revoked_at ? formatDateTime(a.revoked_at, me.preferences) : "-"}</td>
                    {isAdmin && (
                      <td>
                        <div className="actions-cell">
                          <button onClick={() => handleDelete(a)}>Delete</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
