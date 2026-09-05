import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, FleetSshHostKey, Me } from "../api";
import { sshKeyRisk, sshKeyRiskLabel } from "../lib/sshKeyRisk";
import PageHeader from "../components/PageHeader";
import TruncationNotice from "../components/TruncationNotice";
import TableExport from "../components/TableExport";

type SortKey = "host" | "port" | "key_type" | "bits" | "shared" | "risk";
type SortDirection = "asc" | "desc";

const RISK_RANK: Record<string, number> = { dsa: 0, "weak-rsa": 1, ok: 2 };

function compareKeys(a: FleetSshHostKey, b: FleetSshHostKey, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "host":
      return sign * (a.host_hostname || a.host_ip).localeCompare(b.host_hostname || b.host_ip);
    case "port":
      return sign * (a.port - b.port);
    case "key_type":
      return sign * a.key_type.localeCompare(b.key_type);
    case "bits":
      return sign * ((a.bits ?? 0) - (b.bits ?? 0));
    case "shared":
      return sign * (a.shared_ip_count - b.shared_ip_count);
    case "risk":
      return sign * (RISK_RANK[sshKeyRisk(a.key_type, a.bits)] - RISK_RANK[sshKeyRisk(b.key_type, b.bits)]);
    default:
      return 0;
  }
}

export default function SshKeys({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [keys, setKeys] = useState<FleetSshHostKey[]>([]);
  const [truncation, setTruncation] = useState<{ total: number; limit: number } | null>(null);
  const [loading, setLoading] = useState(true);
  // Default sort mirrors what the endpoint already returns: the shared
  // keys, which are the reason this page exists, first.
  const [sortKey, setSortKey] = useState<SortKey>("shared");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [query, setQuery] = useState("");
  const [onlyShared, setOnlyShared] = useState(false);
  const [onlyWeak, setOnlyWeak] = useState(false);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const result = await api.sshHostKeys();
      setKeys(result.items);
      setTruncation(result.truncated ? { total: result.total, limit: result.limit } : null);
    } finally {
      setLoading(false);
    }
  }

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      // Both "shared" and "risk" are most useful worst-first, unlike the
      // plain alphabetical/numeric columns.
      setSortDirection(key === "shared" ? "desc" : "asc");
    }
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  const sharedGroups = useMemo(() => {
    const fingerprints = new Set(keys.filter((k) => k.shared_ip_count > 1).map((k) => k.fingerprint_sha256));
    return fingerprints.size;
  }, [keys]);
  const weakCount = useMemo(() => keys.filter((k) => sshKeyRisk(k.key_type, k.bits) !== "ok").length, [keys]);

  const trimmedQuery = query.trim().toLowerCase();
  const filteredKeys = keys.filter((k) => {
    if (onlyShared && k.shared_ip_count < 2) return false;
    if (onlyWeak && sshKeyRisk(k.key_type, k.bits) === "ok") return false;
    if (!trimmedQuery) return true;
    return (
      k.host_ip.toLowerCase().includes(trimmedQuery) ||
      (k.host_hostname ?? "").toLowerCase().includes(trimmedQuery) ||
      k.key_type.toLowerCase().includes(trimmedQuery) ||
      k.fingerprint_sha256.toLowerCase().includes(trimmedQuery) ||
      (k.fingerprint_md5 ?? "").toLowerCase().includes(trimmedQuery) ||
      String(k.port).includes(trimmedQuery)
    );
  });
  const sortedKeys = [...filteredKeys].sort((a, b) => compareKeys(a, b, sortKey, sortDirection));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>SSH Host Keys</h2>

      {truncation && <TruncationNotice total={truncation.total} limit={truncation.limit} noun="SSH host keys" />}
      <p className="host-meta">
        Every SSH host key seen across the fleet. A host key identifies one machine, so the same fingerprint on
        several addresses usually means a cloned VM or golden image that shipped its keys - or one genuinely
        shared private key. A multi-homed host serving the same key on two of its own addresses looks identical
        here, so confirm before acting on it.
      </p>

      {keys.length > 0 && (
        <>
          <div className="summary-cards">
            <div className="summary-card">
              <span className="summary-card-value">{keys.length}</span>
              <span className="summary-card-label">host keys</span>
            </div>
            <div className={`summary-card${sharedGroups > 0 ? " summary-card-warn" : ""}`}>
              <span className="summary-card-value">{sharedGroups}</span>
              <span className="summary-card-label">shared across addresses</span>
            </div>
            <div className={`summary-card${weakCount > 0 ? " summary-card-warn" : ""}`}>
              <span className="summary-card-value">{weakCount}</span>
              <span className="summary-card-label">weak algorithm / size</span>
            </div>
          </div>

          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by host, port, key type, or fingerprint..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <div className="list-controls">
            <div className="list-controls-filters">
              <label className="hide-empty-toggle">
                <input type="checkbox" checked={onlyShared} onChange={(e) => setOnlyShared(e.target.checked)} />
                Only keys shared across addresses
              </label>
              <label className="hide-empty-toggle">
                <input type="checkbox" checked={onlyWeak} onChange={(e) => setOnlyWeak(e.target.checked)} />
                Only weak keys
              </label>
            </div>
            <TableExport
              rows={sortedKeys}
              filenameBase="porttorch-ssh-host-keys"
              columns={[
                { header: "host", value: (k) => k.host_hostname || k.host_ip },
                { header: "host_ip", value: (k) => k.host_ip },
                { header: "port", value: (k) => k.port },
                { header: "key_type", value: (k) => k.key_type },
                { header: "bits", value: (k) => k.bits },
                { header: "fingerprint_sha256", value: (k) => k.fingerprint_sha256 },
                { header: "fingerprint_md5", value: (k) => k.fingerprint_md5 },
                { header: "shared_ip_count", value: (k) => k.shared_ip_count },
                { header: "risk", value: (k) => sshKeyRisk(k.key_type, k.bits) },
              ]}
            />
          </div>
          <p className="host-meta">
            {trimmedQuery || onlyShared || onlyWeak
              ? `${sortedKeys.length} of ${keys.length} shown`
              : `${keys.length} total`}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : keys.length === 0 ? (
        <p className="empty">
          No SSH host keys captured yet. They are collected by nmap's ssh-hostkey script whenever a scan finds an
          SSH service.
        </p>
      ) : sortedKeys.length === 0 ? (
        <p className="empty">No host keys match the current search/filter.</p>
      ) : (
        <div className="table-scroll">
          <table className="sortable">
            <thead>
              <tr>
                <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
                <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
                <th onClick={() => setSort("key_type")}>Type{sortIndicator("key_type")}</th>
                <th onClick={() => setSort("bits")}>Bits{sortIndicator("bits")}</th>
                <th>Fingerprint (SHA-256)</th>
                <th onClick={() => setSort("shared")}>Shared{sortIndicator("shared")}</th>
                <th onClick={() => setSort("risk")}>Algorithm{sortIndicator("risk")}</th>
              </tr>
            </thead>
            <tbody>
              {sortedKeys.map((k) => {
                const risk = sshKeyRisk(k.key_type, k.bits);
                return (
                  <tr key={k.id}>
                    <td>
                      <Link to={`/hosts/${k.host_id}`}>{k.host_hostname || k.host_ip}</Link>
                    </td>
                    <td>{k.port}</td>
                    <td>{k.key_type}</td>
                    <td>{k.bits ?? "-"}</td>
                    <td className="fingerprint-cell">{k.fingerprint_sha256 || "-"}</td>
                    <td>
                      {k.shared_ip_count > 1 ? (
                        <button
                          type="button"
                          className="link-button"
                          title="Show every host serving this exact key"
                          onClick={() => setQuery(k.fingerprint_sha256)}
                        >
                          {k.shared_ip_count} addresses
                        </button>
                      ) : (
                        "unique"
                      )}
                    </td>
                    <td>
                      {risk === "ok" ? (
                        <span className="expiry-label expiry-ok">ok</span>
                      ) : (
                        <span className="expiry-label expiry-expired">{sshKeyRiskLabel(risk)}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
