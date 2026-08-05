import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, DigestResult, Me } from "../api";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

type Category = "new" | "opened" | "closed";
const CATEGORIES: Array<{ key: Category; label: string }> = [
  { key: "new", label: "New hosts" },
  { key: "opened", label: "Newly opened" },
  { key: "closed", label: "Newly closed" },
];

function hostMatches(ip: string, hostname: string | null, query: string): boolean {
  return ip.toLowerCase().includes(query) || (hostname ?? "").toLowerCase().includes(query);
}

function portMatches(ports: Array<{ port: number; service_name: string | null }>, query: string): boolean {
  return ports.some((p) => String(p.port).includes(query) || (p.service_name ?? "").toLowerCase().includes(query));
}

// <input type="datetime-local">'s value has no timezone - it's always the
// browser's local time, so formatting/parsing both go through plain
// Date methods (getHours, not getUTCHours) and new Date(localString) to
// stay consistent with what the picker itself is showing the user.
function toLocalInputValue(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export default function Digest({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [toInput, setToInput] = useState(() => toLocalInputValue(new Date()));
  const [fromInput, setFromInput] = useState(() => toLocalInputValue(new Date(Date.now() - 24 * 60 * 60 * 1000)));
  const [digest, setDigest] = useState<DigestResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [categories, setCategories] = useState<Set<Category>>(new Set(["new", "opened", "closed"]));

  useEffect(() => {
    load(fromInput, toInput);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromInput, toInput]);

  async function load(from: string, to: string) {
    if (!from || !to) return;
    setLoading(true);
    try {
      setDigest(await api.digest(new Date(from).toISOString(), new Date(to).toISOString()));
    } finally {
      setLoading(false);
    }
  }

  function toggleCategory(c: Category) {
    setCategories((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  }

  const trimmedQuery = query.trim().toLowerCase();

  const newHosts = categories.has("new")
    ? (digest?.newHosts ?? []).filter((h) => !trimmedQuery || hostMatches(h.ip, h.hostname, trimmedQuery))
    : [];

  const changedHosts = (digest?.changedHosts ?? [])
    .map((h) => ({
      ...h,
      newlyOpen: categories.has("opened") ? h.newlyOpen : [],
      newlyClosed: categories.has("closed") ? h.newlyClosed : [],
    }))
    .filter((h) => h.newlyOpen.length > 0 || h.newlyClosed.length > 0)
    .filter(
      (h) =>
        !trimmedQuery ||
        hostMatches(h.ip, h.hostname, trimmedQuery) ||
        portMatches(h.newlyOpen, trimmedQuery) ||
        portMatches(h.newlyClosed, trimmedQuery)
    );

  const totalRaw = (digest?.newHosts.length ?? 0) + (digest?.changedHosts.length ?? 0);
  const totalShown = newHosts.length + changedHosts.length;
  const isEmpty = digest !== null && totalRaw === 0;
  const noMatches = digest !== null && totalRaw > 0 && totalShown === 0;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Digest</h2>

      <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
        <input
          placeholder="Search by host, port, or service..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </form>

      <div className="list-controls">
        <div className="filter-chips">
          {CATEGORIES.map((c) => (
            <button
              key={c.key}
              className={`chip ${categories.has(c.key) ? "active" : ""}`}
              onClick={() => toggleCategory(c.key)}
            >
              {c.label}
            </button>
          ))}
        </div>
        <div className="list-controls-filters">
          <label className="hide-empty-toggle">
            From
            <input type="datetime-local" value={fromInput} onChange={(e) => setFromInput(e.target.value)} />
          </label>
          <label className="hide-empty-toggle">
            To
            <input type="datetime-local" value={toInput} onChange={(e) => setToInput(e.target.value)} />
          </label>
        </div>
      </div>

      {!isEmpty && (trimmedQuery || categories.size < 3) && (
        <p className="host-meta">
          {totalShown} of {totalRaw} shown
        </p>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : isEmpty ? (
        <p className="empty">No new hosts or port changes in the selected window.</p>
      ) : noMatches ? (
        <p className="empty">No changes match the current search/filter.</p>
      ) : (
        <>
          {newHosts.length > 0 && (
            <section>
              <h2>New hosts discovered ({newHosts.length})</h2>
              <ul className="facet-list">
                {newHosts.map((h) => (
                  <li key={h.id}>
                    <Link to={`/hosts/${h.id}`}>{h.hostname || h.ip}</Link>{" "}
                    <span className="host-meta">
                      {formatDateTime(h.observedAt, me.preferences)} · {h.scannerAgentName ?? "?"}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {changedHosts.length > 0 && (
            <section>
              <h2>Hosts with port changes ({changedHosts.length})</h2>
              <div className="banner-list">
                {changedHosts.map((h) => (
                  <div key={h.id} className="banner-card">
                    <div className="banner-card-header">
                      <Link to={`/hosts/${h.id}`}>{h.hostname || h.ip}</Link>
                    </div>
                    <p className="host-meta">
                      {formatDateTime(h.observedAt, me.preferences)} · {h.scannerAgentName ?? "?"}
                    </p>
                    {h.newlyOpen.length > 0 && (
                      <p>
                        <strong>Newly open:</strong>{" "}
                        {h.newlyOpen.map((p) => p.port + (p.service_name ? `/${p.service_name}` : "")).join(", ")}
                      </p>
                    )}
                    {h.newlyClosed.length > 0 && (
                      <p>
                        <strong>Closed:</strong>{" "}
                        {h.newlyClosed.map((p) => p.port + (p.service_name ? `/${p.service_name}` : "")).join(", ")}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
