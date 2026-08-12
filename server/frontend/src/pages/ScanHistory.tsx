import { FormEvent, useEffect, useState } from "react";
import { api, Me, ScanHistoryResult } from "../api";
import { IconInfo, IconSearch } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScanProgressModal from "../components/ScanProgressModal";
import { formatDateTime } from "../lib/formatDate";
import { durationLabel } from "../lib/elapsed";

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
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [statuses, setStatuses] = useState<Set<string>>(new Set(STATUSES));
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey>("started_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [result, setResult] = useState<ScanHistoryResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailsJobId, setDetailsJobId] = useState<string | null>(null);

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

      {loading ? (
        <p>Loading...</p>
      ) : items.length === 0 ? (
        <p className="empty">No scan jobs match the current search/filter.</p>
      ) : (
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
                <td>{s.target_spec}</td>
                <td>{s.port_spec}</td>
                <td>{s.scanner_agent_name ?? "?"}</td>
                <td>
                  <span className={`scan-status scan-status-${s.status}`}>{s.status}</span>
                </td>
                <td>{formatDateTime(s.started_at, me.preferences)}</td>
                <td>{s.duration_ms !== null ? durationLabel(s.duration_ms) : "-"}</td>
                <td>{s.hosts_scanned}</td>
                <td>{s.open_ports_found}</td>
                <td>{s.screenshots + s.rdp_screenshots}</td>
                <td>{s.tls_certificates}</td>
                <td>
                  <button className="btn-icon-label" onClick={() => setDetailsJobId(s.id)}>
                    <IconInfo /> Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
        <ScanProgressModal jobId={detailsJobId} live={false} onClose={() => setDetailsJobId(null)} />
      )}
    </div>
  );
}
