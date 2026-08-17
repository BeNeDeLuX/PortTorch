import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, FleetNucleiFinding, Me } from "../api";
import PageHeader from "../components/PageHeader";

type SortKey = "host" | "port" | "template_id" | "severity";
type SortDirection = "asc" | "desc";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;

function compareFindings(a: FleetNucleiFinding, b: FleetNucleiFinding, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "host":
      return sign * (a.host_hostname || a.host_ip).localeCompare(b.host_hostname || b.host_ip);
    case "port":
      return sign * (a.port - b.port);
    case "template_id":
      return sign * a.template_id.localeCompare(b.template_id);
    case "severity": {
      const av = SEVERITY_RANK[a.severity] ?? 99;
      const bv = SEVERITY_RANK[b.severity] ?? 99;
      return sign * (av - bv);
    }
    default:
      return 0;
  }
}

// Fleet-wide view of nuclei web-vulnerability-scanning findings - own page
// rather than folded into /vulnerabilities, since a template match
// (template-id/severity/tags) doesn't map onto that page's CVE/CPE/CVSS/
// EPSS/KEV shape at all. See CLAUDE.md's nuclei section.
export default function NucleiFindings({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [findings, setFindings] = useState<FleetNucleiFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setFindings(await api.nucleiFindings());
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
  const filtered = findings.filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (!trimmedQuery) return true;
    return (
      f.host_ip.toLowerCase().includes(trimmedQuery) ||
      (f.host_hostname ?? "").toLowerCase().includes(trimmedQuery) ||
      f.template_id.toLowerCase().includes(trimmedQuery) ||
      f.name.toLowerCase().includes(trimmedQuery)
    );
  });
  const sorted = [...filtered].sort((a, b) => compareFindings(a, b, sortKey, sortDirection));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Nuclei Findings</h2>
      <p className="host-meta">
        Web-application findings from nuclei template scans against discovered HTTP(S) ports across the whole
        fleet, most severe first - exposed panels/config, known CVEs, and misconfigurations, depending on which
        nuclei profile a scan used (see Scanning → Nuclei Profiles). Only ever populated for a scan that had a
        non-"Off" nuclei profile selected.
      </p>

      {findings.length > 0 && (
        <>
          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by host, template id, or name..."
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
            {query.trim() || severityFilter ? `${sorted.length} of ${findings.length} shown` : `${findings.length} total`}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : findings.length === 0 ? (
        <p className="empty">No nuclei findings yet.</p>
      ) : sorted.length === 0 ? (
        <p className="empty">No findings match the current search/filter.</p>
      ) : (
        <table className="sortable">
          <thead>
            <tr>
              <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
              <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
              <th onClick={() => setSort("template_id")}>Template{sortIndicator("template_id")}</th>
              <th onClick={() => setSort("severity")}>Severity{sortIndicator("severity")}</th>
              <th>Matched at</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id}>
                <td>
                  <Link to={`/hosts/${f.host_id}`}>{f.host_hostname || f.host_ip}</Link>
                </td>
                <td>{f.port}</td>
                <td>
                  <span className={`cve-badge cve-${f.severity}`}>{f.template_id}</span>
                </td>
                <td>{f.severity}</td>
                <td className="banner">{f.matched_at}</td>
                <td className="audit-details">{f.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
