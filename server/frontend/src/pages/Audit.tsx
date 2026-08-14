import { FormEvent, useEffect, useState } from "react";
import { api, auditExportUrl, AuditEntry, Me } from "../api";
import { IconDownload, IconSearch, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

const PAGE_SIZE = 50;

function formatDetailValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

// Renders details as "key: value (resolved name)" pairs, one per key,
// instead of a raw JSON.stringify dump - lets an id-shaped value (e.g.
// scanner_agent_id) show its resolved name right next to it, per
// AuditEntry.resolvedNames (see api.ts / server/src/audit/resolveNames.ts).
function AuditDetails({ entry }: { entry: AuditEntry }) {
  if (!entry.details) return <>-</>;
  const pairs = Object.entries(entry.details);
  if (pairs.length === 0) return <>-</>;
  return (
    <>
      {pairs.map(([key, value], i) => (
        <span key={key}>
          {i > 0 && ", "}
          {key}: {formatDetailValue(value)}
          {entry.resolvedNames[key] && <strong> ({entry.resolvedNames[key]})</strong>}
        </span>
      ))}
    </>
  );
}

export default function Audit({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [queryInput, setQueryInput] = useState("");
  const [q, setQ] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");

  useEffect(() => {
    load(page, q, from, until);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, q, from, until]);

  async function load(pageNum: number, query: string, fromDate: string, untilDate: string) {
    setLoading(true);
    try {
      const result = await api.audit(pageNum, PAGE_SIZE, query, fromDate, untilDate);
      setEntries(result.items);
      setTotal(result.total);
    } finally {
      setLoading(false);
    }
  }

  function applyQuery(e: FormEvent) {
    e.preventDefault();
    setPage(1);
    setQ(queryInput.trim());
  }

  function clearQuery() {
    setQueryInput("");
    setPage(1);
    setQ("");
    setFrom("");
    setUntil("");
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Audit Log</h2>

      <form className="search-bar" onSubmit={applyQuery}>
        <input
          placeholder="Search by event, actor, source IP, or details..."
          value={queryInput}
          onChange={(e) => setQueryInput(e.target.value)}
        />
        <button type="submit" className="btn-icon-label">
          <IconSearch /> Search
        </button>
        {(q || from || until) && (
          <button type="button" className="btn-icon-label" onClick={clearQuery}>
            <IconX /> Clear
          </button>
        )}
        <a className="export-link btn-icon-label push-right" href={auditExportUrl(q, from, until)} download>
          <IconDownload /> Export
        </a>
      </form>

      <div className="list-controls-filters">
        <label className="date-range-filter">
          From
          <input
            type="date"
            value={from}
            onChange={(e) => {
              setPage(1);
              setFrom(e.target.value);
            }}
          />
        </label>
        <label className="date-range-filter">
          until
          <input
            type="date"
            value={until}
            onChange={(e) => {
              setPage(1);
              setUntil(e.target.value);
            }}
          />
        </label>
      </div>

      <p className="host-meta">
        {(() => {
          const parts: string[] = [];
          if (q) parts.push(`matching "${q}"`);
          if (from) parts.push(`from ${from}`);
          if (until) parts.push(`until ${until}`);
          return parts.length > 0 ? `${total} entries ${parts.join(", ")}` : `${total} security-relevant actions`;
        })()}
        , most recent first.
      </p>

      {loading ? (
        <p>Loading...</p>
      ) : entries.length === 0 ? (
        <p className="empty">{q ? "No audit entries match that search." : "No audit entries yet."}</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Actor</th>
              <th>Source IP</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td>{formatDateTime(e.created_at, me.preferences)}</td>
                <td>{e.event}</td>
                <td>{e.actor ?? "-"}</td>
                <td>{e.source_ip ?? "-"}</td>
                <td className="audit-details">
                  <AuditDetails entry={e} />
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
    </div>
  );
}
