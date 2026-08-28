import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, ExpiringCertificate, Me } from "../api";
import { certExpiryStatus, certExpiryLabel } from "../lib/certExpiry";
import PageHeader from "../components/PageHeader";
import TableExport from "../components/TableExport";
import { formatDateOnly } from "../lib/formatDate";

type SortKey = "host" | "port" | "subject_cn" | "issuer_cn" | "not_after" | "status";
type SortDirection = "asc" | "desc";

const STATUS_RANK: Record<string, number> = { expired: 0, soon: 1, ok: 2, unknown: 3 };

function compareCerts(a: ExpiringCertificate, b: ExpiringCertificate, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "host":
      return sign * (a.host_hostname || a.host_ip).localeCompare(b.host_hostname || b.host_ip);
    case "port":
      return sign * (a.port - b.port);
    case "subject_cn":
      return sign * (a.subject_cn ?? "").localeCompare(b.subject_cn ?? "");
    case "issuer_cn":
      return sign * (a.issuer_cn ?? "").localeCompare(b.issuer_cn ?? "");
    case "not_after": {
      const at = a.not_after ? new Date(a.not_after).getTime() : Infinity;
      const bt = b.not_after ? new Date(b.not_after).getTime() : Infinity;
      return sign * (at - bt);
    }
    case "status":
      return sign * (STATUS_RANK[certExpiryStatus(a.not_after)] - STATUS_RANK[certExpiryStatus(b.not_after)]);
    default:
      return 0;
  }
}

export default function Certificates({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [certs, setCerts] = useState<ExpiringCertificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("not_after");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [query, setQuery] = useState("");
  const [onlyExpired, setOnlyExpired] = useState(false);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setCerts(await api.expiringCertificates());
    } finally {
      setLoading(false);
    }
  }

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

  const trimmedQuery = query.trim().toLowerCase();
  const filteredCerts = certs.filter((c) => {
    if (onlyExpired && certExpiryStatus(c.not_after) !== "expired") return false;
    if (!trimmedQuery) return true;
    return (
      c.host_ip.toLowerCase().includes(trimmedQuery) ||
      (c.host_hostname ?? "").toLowerCase().includes(trimmedQuery) ||
      (c.subject_cn ?? "").toLowerCase().includes(trimmedQuery) ||
      (c.issuer_cn ?? "").toLowerCase().includes(trimmedQuery) ||
      String(c.port).includes(trimmedQuery)
    );
  });
  const sortedCerts = [...filteredCerts].sort((a, b) => compareCerts(a, b, sortKey, sortDirection));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Certificates</h2>
      <p className="host-meta">All TLS certificates across every host, soonest-expiring first.</p>

      {certs.length > 0 && (
        <>
          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by host, port, CN, or issuer..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <div className="list-controls">
            <div className="list-controls-filters">
              <label className="hide-empty-toggle">
                <input type="checkbox" checked={onlyExpired} onChange={(e) => setOnlyExpired(e.target.checked)} />
                Only expired certificates
              </label>
            </div>
            <TableExport
              rows={sortedCerts}
              filenameBase="porttorch-certificates"
              columns={[
                { header: "host", value: (c) => c.host_hostname || c.host_ip },
                { header: "host_ip", value: (c) => c.host_ip },
                { header: "port", value: (c) => c.port },
                { header: "subject_cn", value: (c) => c.subject_cn },
                { header: "issuer_cn", value: (c) => c.issuer_cn },
                { header: "self_signed", value: (c) => String(c.self_signed) },
                { header: "not_before", value: (c) => c.not_before },
                { header: "not_after", value: (c) => c.not_after },
                { header: "status", value: (c) => certExpiryStatus(c.not_after) },
                { header: "fingerprint_sha256", value: (c) => c.fingerprint_sha256 },
              ]}
            />
          </div>
          <p className="host-meta">
            {query.trim() || onlyExpired ? `${sortedCerts.length} of ${certs.length} shown` : `${certs.length} total`}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : certs.length === 0 ? (
        <p className="empty">No TLS certificates captured yet.</p>
      ) : sortedCerts.length === 0 ? (
        <p className="empty">No certificates match the current search/filter.</p>
      ) : (
        <div className="table-scroll">
          <table className="sortable">
            <thead>
              <tr>
                <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
                <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
                <th onClick={() => setSort("subject_cn")}>CN{sortIndicator("subject_cn")}</th>
                <th onClick={() => setSort("issuer_cn")}>Issuer{sortIndicator("issuer_cn")}</th>
                <th onClick={() => setSort("not_after")}>Valid until{sortIndicator("not_after")}</th>
                <th onClick={() => setSort("status")}>Status{sortIndicator("status")}</th>
              </tr>
            </thead>
            <tbody>
              {sortedCerts.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link to={`/hosts/${c.host_id}`}>{c.host_hostname || c.host_ip}</Link>
                  </td>
                  <td>{c.port}</td>
                  <td>
                    {c.subject_cn || "-"}
                    {c.self_signed && <span className="chip-inline">self-signed</span>}
                  </td>
                  <td>{c.issuer_cn || "-"}</td>
                  <td>{c.not_after ? formatDateOnly(c.not_after, me.preferences) : "-"}</td>
                  <td>
                    <span className={`expiry-label expiry-${certExpiryStatus(c.not_after)}`}>
                      {certExpiryLabel(c.not_after)}
                    </span>
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
