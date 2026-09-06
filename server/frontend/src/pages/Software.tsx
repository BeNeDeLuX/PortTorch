import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, Me, SoftwareRow, SoftwareSource } from "../api";
import { cveSeverityClass } from "../lib/cveSeverity";
import { formatDateTime } from "../lib/formatDate";
import PageHeader from "../components/PageHeader";
import TableExport from "../components/TableExport";
import TablePager, { pageSlice } from "../components/TablePager";
import TruncationNotice from "../components/TruncationNotice";

type SortKey = "product" | "version" | "hosts" | "ports" | "risk" | "lastSeen";

const SOURCE_LABEL: Record<SoftwareSource, string> = {
  service: "service",
  web: "web app",
  title: "page title",
};

const SOURCE_TITLE: Record<SoftwareSource, string> = {
  service: "nmap identified this from the service running on the port",
  web: "gowitness fingerprinted this from the web page served",
  title: "taken verbatim from the page's HTML title - a label the page gave itself, not a fingerprint",
};
type SortDirection = "asc" | "desc";

// Same order the endpoint sorts by and the Vulnerabilities page uses:
// confirmed-exploited outranks a higher CVSS, because a KEV-listed "high"
// is more urgent than an unexploited "critical".
function riskRank(row: SoftwareRow): number {
  if (row.hasKev) return 1000;
  return row.maxCvssScore ?? -1;
}

function compare(a: SoftwareRow, b: SoftwareRow, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "product":
      return sign * a.product.localeCompare(b.product);
    case "version":
      // An unknown version sorts last either way rather than jumping to
      // the top of an ascending sort as an empty string would.
      if (a.version === b.version) return 0;
      if (a.version === null) return 1;
      if (b.version === null) return -1;
      return sign * a.version.localeCompare(b.version, undefined, { numeric: true });
    case "hosts":
      return sign * (a.hosts - b.hosts);
    case "ports":
      return sign * (a.ports - b.ports);
    case "risk":
      return sign * (riskRank(a) - riskRank(b));
    case "lastSeen":
      return sign * (Date.parse(a.lastSeen) - Date.parse(b.lastSeen));
    default:
      return 0;
  }
}

// The fleet's application inventory. Scan Stats charts the same data, but
// a donut cannot answer "which versions are out there, on how many hosts
// each, and which of them have known CVEs" - and cannot be clicked
// through to the hosts concerned, which is what turns it into a work
// list.
export default function Software({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [rows, setRows] = useState<SoftwareRow[]>([]);
  const [truncation, setTruncation] = useState<{ total: number; limit: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("risk");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [query, setQuery] = useState("");
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [onlyUnknownVersion, setOnlyUnknownVersion] = useState(false);
  const [sourceFilter, setSourceFilter] = useState<"all" | SoftwareSource>("all");
  const [page, setPage] = useState(1);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const result = await api.software();
      setRows(result.items);
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
      // The count and risk columns are most useful biggest-first; the
      // text ones alphabetically.
      setSortDirection(key === "product" || key === "version" ? "asc" : "desc");
    }
    setPage(1);
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  const distinctProducts = useMemo(() => new Set(rows.map((r) => r.product)).size, [rows]);
  const vulnerableCount = useMemo(() => rows.filter((r) => r.cveCount > 0).length, [rows]);
  const unknownVersionCount = useMemo(() => rows.filter((r) => r.version === null).length, [rows]);

  const trimmed = query.trim().toLowerCase();
  const filtered = rows.filter((r) => {
    if (onlyVulnerable && r.cveCount === 0) return false;
    if (onlyUnknownVersion && r.version !== null) return false;
    if (sourceFilter !== "all" && !r.sources.includes(sourceFilter)) return false;
    if (!trimmed) return true;
    return (
      r.product.toLowerCase().includes(trimmed) ||
      (r.version ?? "").toLowerCase().includes(trimmed) ||
      r.scanners.some((s) => s.toLowerCase().includes(trimmed))
    );
  });
  const sorted = [...filtered].sort((a, b) => compare(a, b, sortKey, sortDirection));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Software</h2>

      {truncation && <TruncationNotice total={truncation.total} limit={truncation.limit} noun="software versions" />}
      <p className="host-meta">
        Every application found running anywhere in the fleet - services, web applications, and frameworks. One row
        per product and version, because that is the unit you patch: "we run Samba" is not actionable, "Samba
        4.17.2 on 40 hosts" is. A product whose version could not be determined keeps its own row rather than being
        folded into a neighbouring one.
      </p>
      <p className="host-meta">
        Rows come from three sources, and the Source column says which, because they are not equally reliable. A{" "}
        <strong>service</strong> is what nmap's probe identified on the port - the strongest signal, and the only one
        carrying the CPE that CVEs are matched against. A <strong>web app</strong> is what gowitness fingerprinted in
        the page itself. A <strong>page title</strong> is taken verbatim from the page's HTML title: not an
        identifier at all, but the only place many self-hosted applications show up, so it finds things the other two
        miss - at the cost of also listing generic titles like "Welcome to nginx!". A row seen by more than one
        source is merged rather than repeated. Everything here was reachable over the network; this is not an
        inventory of what is installed.
      </p>

      {rows.length > 0 && (
        <>
          <div className="summary-cards">
            <div className="summary-card">
              <span className="summary-card-value">{distinctProducts}</span>
              <span className="summary-card-label">products</span>
            </div>
            <div className="summary-card">
              <span className="summary-card-value">{rows.length}</span>
              <span className="summary-card-label">product/version pairs</span>
            </div>
            <div className={`summary-card${vulnerableCount > 0 ? " summary-card-warn" : ""}`}>
              <span className="summary-card-value">{vulnerableCount}</span>
              <span className="summary-card-label">with known CVEs</span>
            </div>
            <div className="summary-card">
              <span className="summary-card-value">{unknownVersionCount}</span>
              <span className="summary-card-label">version undetermined</span>
            </div>
          </div>

          <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
            <input
              placeholder="Search by product, version, or scanner..."
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(1);
              }}
            />
          </form>
          <div className="list-controls">
            <div className="list-controls-filters">
              <label className="hide-empty-toggle">
                <input
                  type="checkbox"
                  checked={onlyVulnerable}
                  onChange={(e) => {
                    setOnlyVulnerable(e.target.checked);
                    setPage(1);
                  }}
                />
                Only versions with known CVEs
              </label>
              <label className="hide-empty-toggle">
                <input
                  type="checkbox"
                  checked={onlyUnknownVersion}
                  onChange={(e) => {
                    setOnlyUnknownVersion(e.target.checked);
                    setPage(1);
                  }}
                />
                Only undetermined versions
              </label>
              <label className="hide-empty-toggle">
                Source
                <select
                  value={sourceFilter}
                  onChange={(e) => {
                    setSourceFilter(e.target.value as "all" | SoftwareSource);
                    setPage(1);
                  }}
                >
                  <option value="all">All</option>
                  <option value="service">Services</option>
                  <option value="web">Web applications</option>
                  <option value="title">Page titles</option>
                </select>
              </label>
            </div>
            <TableExport
              rows={sorted}
              filenameBase="porttorch-software"
              columns={[
                { header: "product", value: (r) => r.product },
                { header: "version", value: (r) => r.version },
                { header: "hosts", value: (r) => r.hosts },
                { header: "ports", value: (r) => r.ports },
                { header: "cve_count", value: (r) => r.cveCount },
                { header: "max_cvss_score", value: (r) => r.maxCvssScore },
                { header: "kev", value: (r) => (r.hasKev ? "yes" : "no") },
                { header: "sources", value: (r) => r.sources.join(" ") },
                { header: "scanners", value: (r) => r.scanners.join(" ") },
                { header: "first_seen", value: (r) => r.firstSeen },
                { header: "last_seen", value: (r) => r.lastSeen },
              ]}
            />
          </div>
          <p className="host-meta">
            {trimmed || onlyVulnerable || onlyUnknownVersion || sourceFilter !== "all"
              ? `${sorted.length} of ${rows.length} shown`
              : `${rows.length} total`}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : rows.length === 0 ? (
        <p className="empty">
          No software identified yet. Products come from nmap's service detection, which only runs against ports a
          scan actually found open - so this fills up as scans cover more of the fleet.
        </p>
      ) : sorted.length === 0 ? (
        <p className="empty">No software matches the current search/filter.</p>
      ) : (
        <>
          <div className="table-scroll">
            <table className="sortable">
              <thead>
                <tr>
                  <th onClick={() => setSort("product")}>Product{sortIndicator("product")}</th>
                  <th onClick={() => setSort("version")}>Version{sortIndicator("version")}</th>
                  <th onClick={() => setSort("hosts")}>Hosts{sortIndicator("hosts")}</th>
                  <th onClick={() => setSort("ports")}>Ports{sortIndicator("ports")}</th>
                  <th>Source</th>
                  <th onClick={() => setSort("risk")}>Known CVEs{sortIndicator("risk")}</th>
                  <th>Scanner</th>
                  <th onClick={() => setSort("lastSeen")}>Last seen{sortIndicator("lastSeen")}</th>
                </tr>
              </thead>
              <tbody>
                {pageSlice(sorted, page).map((r) => (
                  <tr key={`${r.product} ${r.version ?? ""}`}>
                    <td>
                      {/* Straight to the host list filtered by this
                          product - the whole point of the page is to get
                          from "this version is a problem" to "these are
                          the machines". */}
                      <Link to={`/?product=${encodeURIComponent(r.product)}`}>{r.product}</Link>
                    </td>
                    <td>{r.version ?? <span className="host-meta">undetermined</span>}</td>
                    <td>{r.hosts}</td>
                    <td>{r.ports}</td>
                    <td>
                      <span className="source-badges">
                        {r.sources.map((src) => (
                          <span key={src} className="tech-badge" title={SOURCE_TITLE[src]}>
                            {SOURCE_LABEL[src]}
                          </span>
                        ))}
                      </span>
                    </td>
                    <td>
                      {r.cveCount === 0 ? (
                        <span className="host-meta">none known</span>
                      ) : (
                        <>
                          <span
                            className={`cve-badge cve-${cveSeverityClass({ cvssScore: r.maxCvssScore })}`}
                            title={
                              r.maxCvssScore === null
                                ? "No CVSS score on the worst known CVE"
                                : `Highest CVSS score among the known CVEs: ${r.maxCvssScore.toFixed(1)}`
                            }
                          >
                            {r.cveCount} CVE{r.cveCount === 1 ? "" : "s"}
                            {r.maxCvssScore !== null && ` · ${r.maxCvssScore.toFixed(1)}`}
                          </span>
                          {r.hasKev && (
                            <span className="kev-badge" title="At least one is in CISA's Known Exploited Vulnerabilities catalog">
                              KEV
                            </span>
                          )}
                        </>
                      )}
                    </td>
                    <td>{r.scanners.length > 0 ? r.scanners.join(", ") : "-"}</td>
                    <td>{formatDateTime(r.lastSeen, me.preferences)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <TablePager page={page} total={sorted.length} onPage={setPage} />
        </>
      )}
    </div>
  );
}
