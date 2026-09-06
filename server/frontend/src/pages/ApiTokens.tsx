import { FormEvent, useEffect, useState } from "react";
import { api, ApiToken, Me, ScannerAgent } from "../api";
import { IconBan, IconCheck, IconEdit, IconPlus, IconSave, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import { formatDateTime } from "../lib/formatDate";

type SortKey = "name" | "last_used_at" | "created_at" | "status";
type SortDirection = "asc" | "desc";

// "Never" (0) needs no date math; the rest are converted to a concrete
// ISO date at creation time (client-side, same "preset -> concrete value"
// approach as Trends' day-range chips) - the backend only ever stores a
// plain expiresAt timestamp or null, it has no concept of "in 30 days".
const EXPIRY_PRESETS: Array<{ label: string; days: number }> = [
  { label: "Never", days: 0 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year", days: 365 },
];

function tokenIsExpired(t: ApiToken): boolean {
  return t.expires_at !== null && new Date(t.expires_at).getTime() < Date.now();
}

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
  const [scope, setScope] = useState<"read" | "read_write">("read");
  // Which token's privileges are being edited, if any. Editing happens
  // inline in its own row rather than in a form above: unlike creation
  // there is nothing to reveal afterwards, and the row already shows the
  // two values being changed.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editScope, setEditScope] = useState<"read" | "read_write">("read");
  const [editScannerIds, setEditScannerIds] = useState<string[]>([]);
  const [scannerAgentIds, setScannerAgentIds] = useState<string[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [expiryDays, setExpiryDays] = useState(0);
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
      const [tokenList, agentList] = await Promise.all([api.apiTokens(), api.agents()]);
      setTokens(tokenList);
      setAgents(agentList.filter((a) => !a.revoked_at));
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const expiresAt = expiryDays > 0 ? new Date(Date.now() + expiryDays * 24 * 60 * 60_000).toISOString() : null;
    const created = await api.createApiToken(name.trim(), expiresAt, scope, scannerAgentIds);
    setNewToken({ name: created.name, token: created.token });
    setName("");
    setExpiryDays(0);
    await load();
  }

  async function handleSaveEdit(id: string) {
    // Takes effect on that token's next request - tokenAuth reads the row
    // per call, so there is no "applies at next login" delay to warn
    // about the way a user's session-cached role has.
    await api.updateApiToken(id, editScope, editScannerIds);
    setEditingId(null);
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
        For external tools (SOAR, enrichment, ticketing) to query host data, trigger rescans, or queue an ad-hoc
        scan against a brand-new target via the REST API. Separate from Scanner Agent keys, which are only for
        scanners submitting scan results.
      </p>
      <p className="host-meta">
        {/* Linked rather than left to the README: the spec is generated from
            the same zod schemas the routes validate against, so it cannot
            drift from what the API actually accepts, while a hand-written
            note can. Both routes are deliberately unauthenticated - a
            browser loading Swagger UI cannot attach a bearer token to its
            own page load, and codegen expects an uncredentialed spec
            fetch - and they expose only the shape of these endpoints, no
            fleet data. */}
        Every endpoint is documented and callable at{" "}
        <a href="/api/v1/docs/" target="_blank" rel="noopener noreferrer">
          /api/v1/docs
        </a>{" "}
        (Swagger UI), with the machine-readable spec at{" "}
        <a href="/api/v1/openapi.json" target="_blank" rel="noopener noreferrer">
          /api/v1/openapi.json
        </a>{" "}
        for generating a client. Use <strong>Authorize</strong> there and paste a token created below to call the
        API from the browser - bearing in mind that <code>rescan</code> and <code>scans/adhoc</code> start real
        scans against your network, not a sandbox.
      </p>

      {newToken && (
        <div className="callout">
          <strong>API token for "{newToken.name}"</strong> (shown only now):
          <pre className="key-reveal">{newToken.token}</pre>
          <button className="btn-icon-label" onClick={() => setNewToken(null)}>
            <IconCheck /> Got it
          </button>
        </div>
      )}

      <form className="inline-form" onSubmit={handleCreate}>
        <input placeholder="Token name, e.g. soar-enrichment" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={expiryDays} onChange={(e) => setExpiryDays(Number(e.target.value))}>
          {EXPIRY_PRESETS.map((p) => (
            <option key={p.days} value={p.days}>
              Expires: {p.label}
            </option>
          ))}
        </select>
        <select value={scope} onChange={(e) => setScope(e.target.value as "read" | "read_write")}>
          <option value="read">Read only</option>
          <option value="read_write">Read and trigger scans</option>
        </select>
        <label className="hide-empty-toggle">
          Scanners
          <ScannerMultiSelect
            agents={agents}
            selectedIds={scannerAgentIds}
            onChange={setScannerAgentIds}
          />
        </label>
        <button type="submit" className="btn-icon-label">
          <IconPlus /> Create
        </button>
      </form>
      <p className="host-meta">
        A read-only token can look hosts up and list them. "Read and trigger scans" additionally lets it start and
        cancel scans and change triage decisions - only give that to something you would trust to scan your network.
        Leaving the scanner selection empty means the token sees every scanner's results; picking some confines it to
        those, the same way a user account can be confined.
      </p>

      {loading ? (
        <p>Loading...</p>
      ) : tokens.length === 0 ? (
        <p className="empty">No API tokens created yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="sortable">
            <thead>
              <tr>
                <th onClick={() => setSort("name")}>Name{sortIndicator("name")}</th>
                <th onClick={() => setSort("last_used_at")}>Last used{sortIndicator("last_used_at")}</th>
                <th onClick={() => setSort("created_at")}>Created{sortIndicator("created_at")}</th>
                <th>Scope</th>
                <th>Scanners</th>
                <th>Expires</th>
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
                  <td>
                    {editingId === t.id ? (
                      <select value={editScope} onChange={(e) => setEditScope(e.target.value as "read" | "read_write")}>
                        <option value="read">read only</option>
                        <option value="read_write">read + scan</option>
                      </select>
                    ) : t.scope === "read_write" ? (
                      <span className="chip-inline" title="Can start and cancel scans and change triage">
                        read + scan
                      </span>
                    ) : (
                      "read only"
                    )}
                  </td>
                  <td>
                    {editingId === t.id ? (
                      <ScannerMultiSelect agents={agents} selectedIds={editScannerIds} onChange={setEditScannerIds} align="left" />
                    ) : t.scanner_agent_ids.length === 0 ? (
                      "all"
                    ) : (
                      t.scanner_agent_ids
                        .map((id) => agents.find((a) => a.id === id)?.name ?? id.slice(0, 8))
                        .join(", ")
                    )}
                  </td>
                  <td>
                    {t.expires_at ? (
                      <>
                        {formatDateTime(t.expires_at, me.preferences)}
                        {tokenIsExpired(t) && !t.revoked_at && <span className="expiry-label expiry-expired"> expired</span>}
                      </>
                    ) : (
                      "never"
                    )}
                  </td>
                  <td>{t.revoked_at ? `revoked ${formatDateTime(t.revoked_at, me.preferences)}` : "active"}</td>
                  <td>
                    <div className="inline-actions">
                      {!t.revoked_at &&
                        (editingId === t.id ? (
                          <>
                            <button className="btn-icon-label" onClick={() => handleSaveEdit(t.id)}>
                              <IconSave /> Save
                            </button>
                            <button className="link-button btn-icon-label" onClick={() => setEditingId(null)}>
                              <IconX /> Cancel
                            </button>
                          </>
                        ) : (
                          <>
                            <button
                              className="btn-icon-label"
                              onClick={() => {
                                setEditingId(t.id);
                                setEditScope(t.scope === "read_write" ? "read_write" : "read");
                                setEditScannerIds(t.scanner_agent_ids);
                              }}
                            >
                              <IconEdit /> Edit
                            </button>
                            <button className="btn-icon-label" onClick={() => handleRevoke(t)}>
                              <IconBan /> Revoke
                            </button>
                          </>
                        ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
