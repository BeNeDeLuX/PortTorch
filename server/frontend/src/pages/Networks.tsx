import { FormEvent, useEffect, useState } from "react";
import { api, Me, MonitoredNetwork, NetworkCoverage, ScannerAgent } from "../api";
import { IconPlus, IconTrash } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

const ALL_SCANNERS = "";

// Coverage below this in the configured window reads as "effectively not
// being scanned" rather than "partially scanned" - a range nobody swept in
// a month is the finding this page exists for.
const COVERAGE_CRITICAL = 0.05;
const COVERAGE_PARTIAL = 0.95;

function coverageClass(n: NetworkCoverage): string {
  if (n.covered_fraction >= COVERAGE_PARTIAL) return "expiry-ok";
  if (n.covered_fraction <= COVERAGE_CRITICAL) return "expiry-expired";
  return "expiry-soon";
}

function coverageLabel(n: NetworkCoverage): string {
  if (n.last_covered_at === null) return "never scanned";
  if (n.covered_fraction >= COVERAGE_PARTIAL) return "covered";
  if (n.covered_fraction <= COVERAGE_CRITICAL) return "not covered";
  return "partial";
}

function formatPercent(fraction: number): string {
  if (fraction === 0) return "0%";
  const percent = fraction * 100;
  // A /32 rescan inside a /16 is 0.0015% - rounding that to "0%" would
  // read as "nothing was scanned", which is not what happened.
  if (percent < 1) return `<1%`;
  return `${Math.round(percent)}%`;
}

export default function Networks({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [networks, setNetworks] = useState<NetworkCoverage[]>([]);
  const [staleDays, setStaleDays] = useState(30);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [label, setLabel] = useState("");
  const [cidr, setCidr] = useState("");
  const [scannerAgentId, setScannerAgentId] = useState(ALL_SCANNERS);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const coverage = await api.networkCoverage();
      setNetworks(coverage.networks);
      setStaleDays(coverage.staleDays);
      if (me.role === "admin") {
        const agentList = await api.agents();
        setAgents(agentList.filter((a) => !a.revoked_at));
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!label.trim() || !cidr.trim()) return;
    setError(null);
    try {
      await api.createNetwork(label.trim(), cidr.trim(), scannerAgentId || null);
      setLabel("");
      setCidr("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add network");
    }
  }

  async function handleDelete(n: MonitoredNetwork) {
    if (!window.confirm(`Stop tracking coverage for "${n.label}" (${n.cidr})?`)) return;
    await api.deleteNetwork(n.id);
    await load();
  }

  const neverScanned = networks.filter((n) => n.last_covered_at === null).length;
  const partial = networks.filter((n) => n.last_covered_at !== null && n.covered_fraction < COVERAGE_PARTIAL).length;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Network Coverage</h2>
      <p className="host-meta">
        Everything else here is built from what scans <em>found</em>, which leaves one question unanswerable: a
        range nobody ever scanned looks exactly like a range with nothing in it. Declare the ranges you own and
        this page measures them against the actual scan history - what share of each range was swept in the last{" "}
        {staleDays} days, when it was last covered at all, and how many hosts are known in it. Coverage is
        recomputed from scan_jobs on every load, so it can never drift from what really ran.
      </p>

      {error && <p className="error">{error}</p>}

      {me.role === "admin" && (
        <form className="schedule-form" onSubmit={handleCreate}>
          <label>
            Label
            <input placeholder="Office LAN" value={label} onChange={(e) => setLabel(e.target.value)} />
          </label>
          <label>
            Range
            <input placeholder="10.0.0.0/24" value={cidr} onChange={(e) => setCidr(e.target.value)} />
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
          <button type="submit" className="btn-icon-label">
            <IconPlus /> Track
          </button>
        </form>
      )}

      {networks.length > 0 && (
        <div className="summary-cards">
          <div className="summary-card">
            <span className="summary-card-value">{networks.length}</span>
            <span className="summary-card-label">tracked ranges</span>
          </div>
          <div className={`summary-card${neverScanned > 0 ? " summary-card-warn" : ""}`}>
            <span className="summary-card-value">{neverScanned}</span>
            <span className="summary-card-label">never scanned</span>
          </div>
          <div className={`summary-card${partial > 0 ? " summary-card-warn" : ""}`}>
            <span className="summary-card-value">{partial}</span>
            <span className="summary-card-label">incompletely covered</span>
          </div>
        </div>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : networks.length === 0 ? (
        <p className="empty">
          {me.role === "admin"
            ? "No tracked ranges yet. Add the networks you are responsible for above."
            : "No tracked ranges yet - an admin can add them on this page."}
        </p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Range</th>
                <th>Scope</th>
                <th>Addresses</th>
                <th>Hosts known</th>
                <th>Coverage ({staleDays}d)</th>
                <th>Last covered</th>
                <th>Status</th>
                {me.role === "admin" && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {networks.map((n) => (
                <tr key={n.id}>
                  <td>
                    {n.label}
                    <br />
                    <span className="host-meta">{n.cidr}</span>
                  </td>
                  <td>{n.scanner_agent_name ?? "All scanners"}</td>
                  <td>{n.address_count.toLocaleString()}</td>
                  <td>
                    {n.host_count}
                    {n.recent_host_count !== n.host_count && (
                      <span className="host-meta"> ({n.recent_host_count} seen recently)</span>
                    )}
                  </td>
                  <td>
                    {formatPercent(n.covered_fraction)}
                    {/* Only where it could change the reading. On a range
                        that already measures as fully covered, an
                        unresolvable scan adds nothing but noise. */}
                    {n.opaque_scan_count > 0 && n.covered_fraction < COVERAGE_PARTIAL && (
                      <span
                        className="chip-inline"
                        title={
                          `${n.opaque_scan_count} completed scan(s) targeted a DNS hostname or IPv6 address. ` +
                          "Hostnames are resolved on the scanner, so the webserver cannot tell which addresses " +
                          "they covered - they are excluded from this figure rather than guessed at."
                        }
                      >
                        +{n.opaque_scan_count} unknown
                      </span>
                    )}
                  </td>
                  <td>{n.last_covered_at ? formatDateTime(n.last_covered_at, me.preferences) : "never"}</td>
                  <td>
                    <span className={`expiry-label ${coverageClass(n)}`}>{coverageLabel(n)}</span>
                  </td>
                  {me.role === "admin" && (
                    <td>
                      <button type="button" className="btn-icon-label" onClick={() => handleDelete(n)}>
                        <IconTrash size={12} /> remove
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
