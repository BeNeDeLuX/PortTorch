import { FormEvent, useEffect, useState } from "react";
import { api, Me, ScanExclude, ScannerAgent } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";

const ALL_SCANNERS = "";
const SCANNER_FILTER_GLOBAL = "__global__";

export default function Excludes({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [excludes, setExcludes] = useState<ScanExclude[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [kind, setKind] = useState<"ip" | "port" | "ip_port">("ip");
  const [value, setValue] = useState("");
  const [scannerAgentId, setScannerAgentId] = useState(ALL_SCANNERS);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [excludeList, agentList] = await Promise.all([api.excludes(), api.agents()]);
      setExcludes(excludeList);
      setAgents(agentList.filter((a) => !a.revoked_at));
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!value.trim()) return;
    setError(null);
    try {
      await api.createExclude(kind, value.trim(), scannerAgentId || null);
      setValue("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create exclude");
    }
  }

  async function handleDelete(x: ScanExclude) {
    if (!window.confirm(`Remove exclude "${x.value}"?`)) return;
    await api.deleteExclude(x.id);
    await load();
  }

  function scopeLabel(x: ScanExclude): string {
    return x.scanner_agent_name ? `Scanner: ${x.scanner_agent_name}` : "All scanners";
  }

  const trimmedQuery = query.trim().toLowerCase();
  const filtered = excludes.filter((x) => {
    if (scannerFilterIds.length > 0) {
      const matchesGlobal = x.scanner_agent_id === null && scannerFilterIds.includes(SCANNER_FILTER_GLOBAL);
      const matchesAgent = x.scanner_agent_id !== null && scannerFilterIds.includes(x.scanner_agent_id);
      if (!matchesGlobal && !matchesAgent) return false;
    }
    if (trimmedQuery) {
      const haystack = `${x.value} ${x.scanner_agent_name ?? ""}`.toLowerCase();
      if (!haystack.includes(trimmedQuery)) return false;
    }
    return true;
  });

  const ipExcludes = filtered.filter((x) => x.kind === "ip");
  const portExcludes = filtered.filter((x) => x.kind === "port");
  const ipPortExcludes = filtered.filter((x) => x.kind === "ip_port");

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Scan Excludes</h2>
      <p className="host-meta">
        IPs/CIDR ranges, ports/port ranges, and specific IP+port combinations here are never scanned - fetched fresh
        before every scan (manual, menu, or queue-triggered), so this list always takes effect immediately. "All
        scanners" is the inherited default; scoping an exclude to one scanner adds to that default rather than
        replacing it - useful since private IP ranges often overlap across scanners sitting in different networks.
        IP+port excludes work differently from the other two: masscan still probes that exact host:port (it has no
        way to skip one port on just one host within a larger range), the result is just dropped before nmap and
        everything after it ever sees it.
      </p>

      {error && <p className="error">{error}</p>}

      <form className="schedule-form" onSubmit={handleCreate}>
        <label>
          Kind
          <select value={kind} onChange={(e) => setKind(e.target.value as "ip" | "port" | "ip_port")}>
            <option value="ip">IP / CIDR</option>
            <option value="port">Port / range</option>
            <option value="ip_port">IP + port combination</option>
          </select>
        </label>
        <label>
          Value
          <input
            placeholder={
              kind === "ip"
                ? "10.0.0.5, 10.0.0.0/24, 10.0.0.1-10.0.0.10, 2001:db8::1, or 2001:db8::/32"
                : kind === "port"
                  ? "3389 or 8000-8010"
                  : "10.0.0.5:3389, 10.0.0.5:8000-8010, or [2001:db8::1]:3389"
            }
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </label>
        <label>
          Scope
          <select value={scannerAgentId} onChange={(e) => setScannerAgentId(e.target.value)}>
            <option value={ALL_SCANNERS}>All scanners (default)</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <button type="submit">Add</button>
      </form>

      {loading ? (
        <p>Loading...</p>
      ) : (
        <>
          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by value or scanner..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <label className="hide-empty-toggle push-right">
            Scanner
            <ScannerMultiSelect
              agents={[{ id: SCANNER_FILTER_GLOBAL, name: "Global (no specific scanner)" }, ...agents]}
              selectedIds={scannerFilterIds}
              onChange={setScannerFilterIds}
              align="right"
            />
          </label>

          <h3>IPs / CIDR ranges ({ipExcludes.length})</h3>
          {ipExcludes.length === 0 ? (
            <p className="empty">No IP excludes match.</p>
          ) : (
            <ul className="facet-list exclude-list">
              {ipExcludes.map((x) => (
                <li key={x.id}>
                  <button className="facet-item" onClick={() => handleDelete(x)}>
                    <span>
                      {x.value} <span className="chip-inline">{scopeLabel(x)}</span>
                    </span>
                    <span className="facet-count">remove</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <h3>Ports / ranges ({portExcludes.length})</h3>
          {portExcludes.length === 0 ? (
            <p className="empty">No port excludes match.</p>
          ) : (
            <ul className="facet-list exclude-list">
              {portExcludes.map((x) => (
                <li key={x.id}>
                  <button className="facet-item" onClick={() => handleDelete(x)}>
                    <span>
                      {x.value} <span className="chip-inline">{scopeLabel(x)}</span>
                    </span>
                    <span className="facet-count">remove</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <h3>IP + port combinations ({ipPortExcludes.length})</h3>
          {ipPortExcludes.length === 0 ? (
            <p className="empty">No IP+port excludes match.</p>
          ) : (
            <ul className="facet-list exclude-list">
              {ipPortExcludes.map((x) => (
                <li key={x.id}>
                  <button className="facet-item" onClick={() => handleDelete(x)}>
                    <span>
                      {x.value} <span className="chip-inline">{scopeLabel(x)}</span>
                    </span>
                    <span className="facet-count">remove</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
