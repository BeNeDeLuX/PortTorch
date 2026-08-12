import { FormEvent, useEffect, useState } from "react";
import { api, AuditEntry, Me } from "../api";
import { IconSearch, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

export default function Audit({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [queryInput, setQueryInput] = useState("");
  const [q, setQ] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");

  useEffect(() => {
    load(q, from, until);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, from, until]);

  async function load(query: string, fromDate: string, untilDate: string) {
    setLoading(true);
    try {
      setEntries(await api.audit(200, query, fromDate, untilDate));
    } finally {
      setLoading(false);
    }
  }

  function applyQuery(e: FormEvent) {
    e.preventDefault();
    setQ(queryInput.trim());
  }

  function clearQuery() {
    setQueryInput("");
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
      </form>

      <div className="list-controls-filters push-right">
        <label className="date-range-filter">
          From
          <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label className="date-range-filter">
          until
          <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
        </label>
      </div>

      <p className="host-meta">
        {(() => {
          const parts: string[] = [];
          if (q) parts.push(`matching "${q}"`);
          if (from) parts.push(`from ${from}`);
          if (until) parts.push(`until ${until}`);
          return parts.length > 0
            ? `${entries.length} entries ${parts.join(", ")}`
            : `Latest ${entries.length} security-relevant actions`;
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
                <td className="audit-details">{e.details ? JSON.stringify(e.details) : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
