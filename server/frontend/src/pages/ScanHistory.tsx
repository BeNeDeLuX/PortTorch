import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { api, Me, ScanHistoryEntry, ScanHistoryResult } from "../api";
import { IconInfo, IconWarning, IconSearch, IconRefresh, IconPlay } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScanProgressModal from "../components/ScanProgressModal";
import { formatDateTime } from "../lib/formatDate";
import { durationLabel } from "../lib/elapsed";
import { anomalyLabel, describeScanAnomaly } from "../lib/scanAnomalies";

const STATUSES = ["completed", "failed", "cancelled"] as const;
const PAGE_SIZE = 50;

type SortKey =
  | "target_spec"
  | "port_spec"
  | "scanner_agent_name"
  | "status"
  | "started_at"
  | "duration_ms"
  | "hosts_scanned"
  | "open_ports_found"
  | "screenshots"
  | "tls_certificates";
type SortDirection = "asc" | "desc";

export default function ScanHistory({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const navigate = useNavigate();
  // Same tier as creating an ad-hoc scan itself (requireOperator on the
  // API side) - a read-only user can see history but not queue work from
  // it, so the button is hidden rather than shown-disabled.
  const canRescan = me.role === "admin" || me.role === "operator";
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [statuses, setStatuses] = useState<Set<string>>(new Set(STATUSES));
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey>("started_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [result, setResult] = useState<ScanHistoryResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailsJobId, setDetailsJobId] = useState<string | null>(null);
  const [resumeNotice, setResumeNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [resumingId, setResumingId] = useState<string | null>(null);

  async function resume(s: ScanHistoryEntry) {
    const remaining = s.remaining_target_spec ?? "";
    const shown = remaining.length > 300 ? `${remaining.slice(0, 300)}...` : remaining;
    if (
      !window.confirm(
        `Queue the part of this scan that never finished?\n\nTarget: ${shown}\nPorts: ${s.port_spec}\nScanner: ${s.scanner_agent_name ?? "?"}\n\nIt runs with the same scan profile, nuclei profile, rate, priority and tags as the original.`
      )
    ) {
      return;
    }
    setResumingId(s.id);
    setResumeNotice(null);
    try {
      const res = await api.resumeScanJob(s.id);
      setResumeNotice({ ok: true, text: `Queued the rest of the scan (${res.targetSpec.length > 120 ? `${res.targetSpec.slice(0, 120)}...` : res.targetSpec}). It waits in the queue on the Scanner Agents page until the scanner picks it up.` });
      await load();
    } catch (err) {
      setResumeNotice({ ok: false, text: err instanceof Error ? err.message : "Failed to resume the scan" });
    } finally {
      setResumingId(null);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, statuses, page, sortKey, sortDirection]);

  async function load() {
    setLoading(true);
    try {
      const statusList = statuses.size < STATUSES.length ? [...statuses] : [];
      setResult(await api.scanHistory(query, statusList, page, PAGE_SIZE, sortKey, sortDirection));
    } finally {
      setLoading(false);
    }
  }

  function applyQuery(e: FormEvent) {
    e.preventDefault();
    setPage(1);
    setQuery(queryInput.trim());
  }

  function toggleStatus(s: string) {
    setStatuses((prev) => {
      if (prev.has(s) && prev.size === 1) return prev; // at least one status must stay selected
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
    setPage(1);
  }

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("asc");
    }
    setPage(1);
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  const items = result?.items ?? [];
  const total = result?.total ?? 0;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Scan History</h2>
      <p className="host-meta">Every finished scan job (completed, failed, or cancelled), most recently finished first.</p>

      <form className="search-bar" onSubmit={applyQuery}>
        <input
          placeholder="Search by target, ports, or scanner..."
          value={queryInput}
          onChange={(e) => setQueryInput(e.target.value)}
        />
        <button type="submit" className="btn-icon-label">
          <IconSearch /> Search
        </button>
      </form>

      <div className="filter-chips">
        {STATUSES.map((s) => (
          <button key={s} className={`chip ${statuses.has(s) ? "active" : ""}`} onClick={() => toggleStatus(s)}>
            {s}
          </button>
        ))}
      </div>

      {resumeNotice && <p className={resumeNotice.ok ? "callout-success" : "callout-danger"}>{resumeNotice.text}</p>}

      {loading ? (
        <p>Loading...</p>
      ) : items.length === 0 ? (
        <p className="empty">No scan jobs match the current search/filter.</p>
      ) : (
        <div className="table-scroll">
          <table className="sortable">
            <thead>
              <tr>
                <th onClick={() => setSort("target_spec")}>Target{sortIndicator("target_spec")}</th>
                <th onClick={() => setSort("port_spec")}>Ports{sortIndicator("port_spec")}</th>
                <th onClick={() => setSort("scanner_agent_name")}>Scanner{sortIndicator("scanner_agent_name")}</th>
                <th onClick={() => setSort("status")}>Status{sortIndicator("status")}</th>
                <th onClick={() => setSort("started_at")}>Started{sortIndicator("started_at")}</th>
                <th onClick={() => setSort("duration_ms")}>Duration{sortIndicator("duration_ms")}</th>
                <th onClick={() => setSort("hosts_scanned")}>Hosts scanned{sortIndicator("hosts_scanned")}</th>
                <th onClick={() => setSort("open_ports_found")}>Open ports{sortIndicator("open_ports_found")}</th>
                <th onClick={() => setSort("screenshots")}>Screenshots{sortIndicator("screenshots")}</th>
                <th onClick={() => setSort("tls_certificates")}>TLS certs{sortIndicator("tls_certificates")}</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td className="spec-cell">
                    {s.target_spec}
                    {(s.anomalies ?? []).map((a, i) => (
                      <span key={i} className="scan-anomaly-badge" title={describeScanAnomaly(a)}>
                        <IconWarning /> {anomalyLabel(a)}
                      </span>
                    ))}
                  </td>
                  <td className="spec-cell">{s.port_spec}</td>
                  <td>{s.scanner_agent_name ?? "?"}</td>
                  <td>
                    <span className={`scan-status scan-status-${s.status}`}>{s.status}</span>
                    {s.remaining_target_spec && (
                      <span className="host-meta" title={`Not finished: ${s.remaining_target_spec}`}>
                        {s.resumed_at ? " · rest queued" : " · partly done"}
                      </span>
                    )}
                  </td>
                  <td>{formatDateTime(s.started_at, me.preferences)}</td>
                  <td>{s.duration_ms !== null ? durationLabel(s.duration_ms) : "-"}</td>
                  {/* Discovery found N, enrichment confirmed M. Shown as a
                      pair only when they differ, so the ordinary case stays
                      one number - the gap is the interesting part, not the
                      first figure on its own. */}
                  <td>
                    {s.hosts_scanned}
                    {s.discovered_hosts !== null && s.discovered_hosts !== s.hosts_scanned && (
                      <span className="host-meta"> of {s.discovered_hosts} found</span>
                    )}
                  </td>
                  <td>{s.open_ports_found}</td>
                  <td>{s.screenshots + s.rdp_screenshots}</td>
                  <td>{s.tls_certificates}</td>
                  <td>
                    <div className="actions-cell">
                      <button className="btn-icon-label" onClick={() => setDetailsJobId(s.id)}>
                        <IconInfo /> Details
                      </button>
                      {canRescan && (
                        <button
                          className="btn-icon-label"
                          title={
                            s.scanner_agent_id
                              ? "Queue this exact target and ports again"
                              : "The scanner that ran this is gone - pick one on the next page"
                          }
                          onClick={() =>
                            navigate("/adhoc-scans", {
                              state: {
                                targetSpec: s.target_spec,
                                portSpec: s.port_spec,
                                ...(s.scanner_agent_id ? { scannerAgentId: s.scanner_agent_id } : {}),
                              },
                            })
                          }
                        >
                          <IconRefresh /> Rescan
                        </button>
                      )}
                      {canRescan && s.remaining_target_spec && !s.resumed_at && s.scanner_agent_id && (
                        <button
                          className="btn-icon-label"
                          title={`Scan only what this ${s.status} scan never finished: ${
                            s.remaining_target_spec.length > 200 ? `${s.remaining_target_spec.slice(0, 200)}...` : s.remaining_target_spec
                          }`}
                          disabled={resumingId === s.id}
                          onClick={() => resume(s)}
                        >
                          <IconPlay /> Resume
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

      {!loading && total > PAGE_SIZE && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            &larr; Prev
          </button>
          <span className="host-meta">
            Showing {(page - 1) * PAGE_SIZE + 1}
            &ndash;{Math.min(page * PAGE_SIZE, total)} of {total}
          </span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)}>
            Next &rarr;
          </button>
        </div>
      )}

      {detailsJobId && (
        <ScanProgressModal
          jobId={detailsJobId}
          live={false}
          // The finished duration the table already shows in its own
          // column - the modal states what the scan took rather than
          // counting up against a clock that stopped.
          durationMs={items.find((i) => i.id === detailsJobId)?.duration_ms ?? null}
          onClose={() => setDetailsJobId(null)}
        />
      )}
    </div>
  );
}
