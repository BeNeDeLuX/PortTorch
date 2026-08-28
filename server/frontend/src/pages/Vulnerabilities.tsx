import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, FleetVulnerability, Me } from "../api";
import { cveSeverityClass } from "../lib/cveSeverity";
import PageHeader from "../components/PageHeader";
import TriageControl from "../components/TriageControl";
import TriageFilterSelect from "../components/TriageFilterSelect";
import BulkTriageBar from "../components/BulkTriageBar";
import TableExport from "../components/TableExport";
import { TriageFilter, matchesTriageFilter, triageCounts } from "../lib/triageFilter";

type SortKey = "host" | "port" | "cve_id" | "cvss_score" | "epss_score" | "kev";
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
    case "kev": {
      const av = a.kev_date_added ? 1 : 0;
      const bv = b.kev_date_added ? 1 : 0;
      return sign * (bv - av);
    }
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
  const [kevOnly, setKevOnly] = useState(false);
  // Defaults to "needs a decision" - the page should open on what still
  // wants attention, not every CVE ever matched. Same default and same
  // control on WebFindings.tsx.
  const [triageFilter, setTriageFilter] = useState<TriageFilter>("needs_decision");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const canEdit = me.role === "admin" || me.role === "operator";

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

  // A CVE finding's identity is (host, cve) - the same pair
  // finding_triage keys on, so a selection can never address something
  // the triage endpoint can't.
  const rowKey = (v: FleetVulnerability) => `${v.host_id}:${v.cve_id}`;

  function toggleRow(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }

  async function applyBulkTriage(state: "false_positive" | "accepted_risk" | "fixed" | null) {
    const targets = sortedVulns.filter((v) => selected.has(rowKey(v)));
    const results = await Promise.allSettled(
      targets.map((v) => {
        const target = { kind: "cve" as const, hostId: v.host_id, cveId: v.cve_id };
        // Clearing an already-open finding 404s server-side, which would
        // count as a spurious failure - skip those rather than report them.
        if (state === null) return v.triage_state ? api.clearFindingTriage(target) : Promise.resolve();
        return api.setFindingTriage(target, state);
      })
    );
    setSelected(new Set());
    await load();
    return {
      succeeded: results.filter((r) => r.status === "fulfilled").length,
      failed: results.filter((r) => r.status === "rejected").length,
    };
  }

  const trimmedQuery = query.trim().toLowerCase();
  const filteredVulns = vulns.filter((v) => {
    if (!matchesTriageFilter(triageFilter, v)) return false;
    if (severityFilter && severityOf(v) !== severityFilter) return false;
    if (kevOnly && !v.kev_date_added) return false;
    if (!trimmedQuery) return true;
    return (
      v.host_ip.toLowerCase().includes(trimmedQuery) ||
      (v.host_hostname ?? "").toLowerCase().includes(trimmedQuery) ||
      v.cve_id.toLowerCase().includes(trimmedQuery) ||
      v.description.toLowerCase().includes(trimmedQuery)
    );
  });
  const sortedVulns = [...filteredVulns].sort((a, b) => compareVulns(a, b, sortKey, sortDirection));
  // Computed against the whole fleet-wide set, not the filtered view -
  // it's a "what exists" summary, so it must not change as the filter
  // narrows (which would make it circular).
  const triageBreakdown = triageCounts(vulns);

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Vulnerabilities</h2>
      <p className="host-meta">
        Known CVEs matched against detected service versions across the whole fleet, most severe first. Synced daily
        from the NVD database - see a host's detail page for per-port context. EPSS (Exploit Prediction Scoring
        System, synced daily from FIRST.org) estimates the probability a CVE is exploited in the wild within the
        next 30 days - useful for prioritizing among CVEs of the same severity. A "KEV" badge means CISA has
        confirmed the CVE is already being actively exploited (its Known Exploited Vulnerabilities catalog, synced
        daily) - a stronger, more concrete signal than EPSS's predicted probability, so KEV-listed rows sort first
        regardless of severity.
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
            <button className={`chip ${kevOnly ? "active" : ""}`} onClick={() => setKevOnly((v) => !v)}>
              Known Exploited (CISA KEV)
            </button>
          </div>
          <div className="list-controls">
            <TriageFilterSelect value={triageFilter} onChange={setTriageFilter} />
            <TableExport
              rows={sortedVulns}
              filenameBase="porttorch-vulnerabilities"
              columns={[
                { header: "host", value: (v) => v.host_hostname || v.host_ip },
                { header: "host_ip", value: (v) => v.host_ip },
                { header: "port", value: (v) => v.port },
                { header: "cve_id", value: (v) => v.cve_id },
                { header: "cvss_score", value: (v) => v.cvss_score },
                { header: "cvss_severity", value: (v) => v.cvss_severity },
                { header: "epss_score", value: (v) => v.epss_score },
                { header: "kev_date_added", value: (v) => v.kev_date_added },
                { header: "kev_ransomware", value: (v) => v.kev_known_ransomware_campaign_use },
                { header: "description", value: (v) => v.description },
                { header: "triage_state", value: (v) => v.triage_state },
                { header: "triage_note", value: (v) => v.triage_note },
                { header: "triage_review_at", value: (v) => v.triage_review_at },
              ]}
            />
          </div>
          {canEdit && (
            <BulkTriageBar
              count={selected.size}
              onApply={applyBulkTriage}
              onClearSelection={() => setSelected(new Set())}
            />
          )}
          <p className="host-meta">
            {query.trim() || severityFilter || kevOnly || triageFilter !== "all"
              ? `${sortedVulns.length} of ${vulns.length} shown`
              : `${vulns.length} total`}
            {triageBreakdown.map((t) => ` · ${t.count} ${t.label.toLowerCase()}`).join("")}
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
        <div className="table-scroll">
          <table className="sortable">
            <thead>
              <tr>
                {canEdit && (
                  <th className="select-col">
                    <input
                      type="checkbox"
                      title="Select every row currently shown"
                      checked={sortedVulns.length > 0 && sortedVulns.every((v) => selected.has(rowKey(v)))}
                      onChange={(e) =>
                        setSelected(e.target.checked ? new Set(sortedVulns.map(rowKey)) : new Set())
                      }
                    />
                  </th>
                )}
                <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
                <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
                <th onClick={() => setSort("cve_id")}>CVE{sortIndicator("cve_id")}</th>
                <th onClick={() => setSort("cvss_score")}>Severity{sortIndicator("cvss_score")}</th>
                <th onClick={() => setSort("epss_score")}>EPSS{sortIndicator("epss_score")}</th>
                <th onClick={() => setSort("kev")}>KEV{sortIndicator("kev")}</th>
                <th>Description</th>
                <th>Triage</th>
              </tr>
            </thead>
            <tbody>
              {sortedVulns.map((v) => (
                <tr key={`${v.host_id}-${v.port}-${v.cve_id}`}>
                  {canEdit && (
                    <td className="select-col">
                      <input type="checkbox" checked={selected.has(rowKey(v))} onChange={() => toggleRow(rowKey(v))} />
                    </td>
                  )}
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
                  <td>
                    {v.kev_date_added && (
                      <span
                        className="kev-badge"
                        title={`Added to CISA KEV ${v.kev_date_added}${v.kev_known_ransomware_campaign_use === "Known" ? " - known ransomware campaign use" : ""}`}
                      >
                        KEV
                      </span>
                    )}
                  </td>
                  <td className="audit-details">{v.description}</td>
                  <td>
                    <TriageControl
                      target={{ kind: "cve", hostId: v.host_id, cveId: v.cve_id }}
                      state={v.triage_state}
                      note={v.triage_note}
                      reviewAt={v.triage_review_at}
                      expired={v.triage_expired}
                      canEdit={canEdit}
                      onChanged={load}
                    />
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
