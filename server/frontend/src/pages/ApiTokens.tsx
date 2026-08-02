import { FormEvent, useEffect, useState } from "react";
import { api, ApiToken, Me } from "../api";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

type SortKey = "name" | "last_used_at" | "created_at" | "status";
type SortDirection = "asc" | "desc";

function compareTokens(a: ApiToken, b: ApiToken, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "name":
      return sign * a.name.localeCompare(b.name);
    case "last_used_at": {
      const at = a.last_used_at ? new Date(a.last_used_at).getTime() : -Infinity;
      const bt = b.last_used_at ? new Date(b.last_used_at).getTime() : -Infinity;
      return sign * (at - bt);
    }
    case "created_at":
      return sign * (new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
    case "status": {
      const av = a.revoked_at ? 1 : 0;
      const bv = b.revoked_at ? 1 : 0;
      return sign * (av - bv);
    }
    default:
      return 0;
  }
}

export default function ApiTokens({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [name, setName] = useState("");
  const [newToken, setNewToken] = useState<{ name: string; token: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

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

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setTokens(await api.apiTokens());
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const created = await api.createApiToken(name.trim());
    setNewToken({ name: created.name, token: created.token });
    setName("");
    await load();
  }

  async function handleRevoke(t: ApiToken) {
    if (!window.confirm(`Revoke "${t.name}"? Any tool using this token will stop being able to authenticate.`)) {
      return;
    }
    await api.revokeApiToken(t.id);
    await load();
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>API Tokens</h2>
      <p className="host-meta">
        For external tools (SOAR, enrichment, ticketing) to query host data and trigger rescans via the REST API -
        see <code>GET/POST /api/v1/hosts/...</code> in the README. Separate from Scanner Agent keys, which are only
        for scanners submitting scan results.
      </p>

      {newToken && (
        <div className="callout">
          <strong>API token for "{newToken.name}"</strong> (shown only now):
          <pre className="key-reveal">{newToken.token}</pre>
          <button onClick={() => setNewToken(null)}>Got it</button>
        </div>
      )}

      <form className="inline-form" onSubmit={handleCreate}>
        <input placeholder="Token name, e.g. soar-enrichment" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit">Create</button>
      </form>

      {loading ? (
        <p>Loading...</p>
      ) : tokens.length === 0 ? (
        <p className="empty">No API tokens created yet.</p>
      ) : (
        <table className="sortable">
          <thead>
            <tr>
              <th onClick={() => setSort("name")}>Name{sortIndicator("name")}</th>
              <th onClick={() => setSort("last_used_at")}>Last used{sortIndicator("last_used_at")}</th>
              <th onClick={() => setSort("created_at")}>Created{sortIndicator("created_at")}</th>
              <th onClick={() => setSort("status")}>Status{sortIndicator("status")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {[...tokens].sort((a, b) => compareTokens(a, b, sortKey, sortDirection)).map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td>{t.last_used_at ? formatDateTime(t.last_used_at, me.preferences) : "never"}</td>
                <td>{formatDateTime(t.created_at, me.preferences)}</td>
                <td>{t.revoked_at ? `revoked ${formatDateTime(t.revoked_at, me.preferences)}` : "active"}</td>
                <td>{!t.revoked_at && <button onClick={() => handleRevoke(t)}>Revoke</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
