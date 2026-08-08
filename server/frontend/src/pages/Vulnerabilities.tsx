import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, FleetVulnerability, Me } from "../api";
import { cveSeverityClass } from "../lib/cveSeverity";
import PageHeader from "../components/PageHeader";

type SortKey = "host" | "port" | "cve_id" | "cvss_score" | "epss_score";
type SortDirection = "asc" | "desc";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITIES = ["critical", "high", "medium", "low"] as const;

// FleetVulnerability uses the DB's snake_case column names; cveSeverityClass
// expects the camelCase shape shared with the per-host CveEntry type.
function severityOf(v: FleetVulnerability) {
  return cveSeverityClass({ cvssScore: v.cvss_score, cvssSeverity: v.cvss_severity });
}

function compareVulns(a: FleetVulnerability, b: FleetVulnerability, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "host":
      return sign * (a.host_hostname || a.host_ip).localeCompare(b.host_hostname || b.host_ip);
    case "port":
      return sign * (a.port - b.port);
    case "cve_id":
      return sign * a.cve_id.localeCompare(b.cve_id);
    case "cvss_score": {
      const av = SEVERITY_RANK[severityOf(a)];
      const bv = SEVERITY_RANK[severityOf(b)];
      if (av !== bv) return sign * (av - bv);
      return sign * ((b.cvss_score ?? 0) - (a.cvss_score ?? 0));
    }
    case "epss_score":
      return sign * ((b.epss_score ?? -1) - (a.epss_score ?? -1));
    default:
      return 0;
  }
}

export default function Vulnerabilities({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [vulns, setVulns] = useState<FleetVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("cvss_score");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setVulns(await api.vulnerabilities());
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
  const filteredVulns = vulns.filter((v) => {
    if (severityFilter && severityOf(v) !== severityFilter) return false;
    if (!trimmedQuery) return true;
    return (
      v.host_ip.toLowerCase().includes(trimmedQuery) ||
      (v.host_hostname ?? "").toLowerCase().includes(trimmedQuery) ||
      v.cve_id.toLowerCase().includes(trimmedQuery) ||
      v.description.toLowerCase().includes(trimmedQuery)
    );
  });
  const sortedVulns = [...filteredVulns].sort((a, b) => compareVulns(a, b, sortKey, sortDirection));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Vulnerabilities</h2>
      <p className="host-meta">
        Known CVEs matched against detected service versions across the whole fleet, most severe first. Synced daily
        from the NVD database - see a host's detail page for per-port context. EPSS (Exploit Prediction Scoring
        System, synced daily from FIRST.org) estimates the probability a CVE is exploited in the wild within the
        next 30 days - useful for prioritizing among CVEs of the same severity.
      </p>

      {vulns.length > 0 && (
        <>
          <form
            className="search-bar"
            onSubmit={(e) => e.preventDefault()}
          >
            <input
              placeholder="Search by host, CVE id, or description..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <div className="filter-chips">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                className={`chip ${severityFilter === s ? "active" : ""}`}
                onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
              >
                {s}
              </button>
            ))}
          </div>
          <p className="host-meta">
            {query.trim() || severityFilter ? `${sortedVulns.length} of ${vulns.length} shown` : `${vulns.length} total`}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : vulns.length === 0 ? (
        <p className="empty">No known vulnerabilities matched yet.</p>
      ) : sortedVulns.length === 0 ? (
        <p className="empty">No vulnerabilities match the current search/filter.</p>
      ) : (
        <table className="sortable">
          <thead>
            <tr>
              <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
              <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
              <th onClick={() => setSort("cve_id")}>CVE{sortIndicator("cve_id")}</th>
              <th onClick={() => setSort("cvss_score")}>Severity{sortIndicator("cvss_score")}</th>
              <th onClick={() => setSort("epss_score")}>EPSS{sortIndicator("epss_score")}</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {sortedVulns.map((v) => (
              <tr key={`${v.host_id}-${v.port}-${v.cve_id}`}>
                <td>
                  <Link to={`/hosts/${v.host_id}`}>{v.host_hostname || v.host_ip}</Link>
                </td>
                <td>{v.port}</td>
                <td>
                  <a
                    className={`cve-badge cve-${severityOf(v)}`}
                    href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {v.cve_id}
                  </a>
                </td>
                <td>
                  {severityOf(v)}
                  {v.cvss_score != null && ` (${v.cvss_score})`}
                </td>
                <td title={v.epss_percentile != null ? `${Math.round(v.epss_percentile * 100)}th percentile` : undefined}>
                  {v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : "-"}
                </td>
                <td className="audit-details">{v.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
