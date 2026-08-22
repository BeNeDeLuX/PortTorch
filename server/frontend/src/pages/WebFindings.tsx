import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, FleetNucleiFinding, Me } from "../api";
import PageHeader from "../components/PageHeader";
import TriageControl from "../components/TriageControl";
import TriageFilterSelect from "../components/TriageFilterSelect";
import BulkTriageBar from "../components/BulkTriageBar";
import TableExport from "../components/TableExport";
import { TriageFilter, matchesTriageFilter, triageCounts } from "../lib/triageFilter";

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

// Fleet-wide view of nuclei web-vulnerability-scanning findings - "Web
// Findings" rather than "Nuclei Findings" as the user-facing name (nuclei
// is an implementation detail, already explained in the description below)
// - own page rather than folded into /vulnerabilities, since a template
// match (template-id/severity/tags) doesn't map onto that page's CVE/CPE/
// CVSS/EPSS/KEV shape at all. See CLAUDE.md's nuclei section.
export default function WebFindings({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [findings, setFindings] = useState<FleetNucleiFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  // Defaults to "needs a decision" so the page opens on what still wants
  // attention rather than everything ever found. The other options exist
  // because "what did we already dismiss, and why" is a real question too
  // (e.g. reviewing a previous analyst's calls). Same control and default
  // as Vulnerabilities.tsx.
  const [triageFilter, setTriageFilter] = useState<TriageFilter>("needs_decision");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const canEdit = me.role === "admin" || me.role === "operator";

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

  // A nuclei finding's identity is (host, template, matched_at) - the
  // same triple finding_triage keys on, and deliberately not the
  // nuclei_findings row id, which is re-inserted on every rescan.
  const rowKey = (f: FleetNucleiFinding) => `${f.host_id}:${f.template_id}:${f.matched_at}`;

  function toggleRow(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }

  async function applyBulkTriage(state: "false_positive" | "accepted_risk" | "fixed" | null) {
    const targets = sorted.filter((f) => selected.has(rowKey(f)));
    const results = await Promise.allSettled(
      targets.map((f) => {
        const target = { kind: "nuclei" as const, hostId: f.host_id, templateId: f.template_id, matchedAt: f.matched_at };
        // Clearing an untriaged finding 404s server-side; skipping those
        // keeps them out of the failure count.
        if (state === null) return f.triage_state ? api.clearFindingTriage(target) : Promise.resolve();
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
  const filtered = findings.filter((f) => {
    if (!matchesTriageFilter(triageFilter, f)) return false;
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
  // Against the whole set, not the filtered view - a "what exists"
  // summary that must not shift as the filter narrows.
  const triageBreakdown = triageCounts(findings);

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Web Findings</h2>
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
          <div className="list-controls">
            <TriageFilterSelect value={triageFilter} onChange={setTriageFilter} />
            <TableExport
              rows={sorted}
              filenameBase="porttorch-web-findings"
              columns={[
                { header: "host", value: (f) => f.host_hostname || f.host_ip },
                { header: "host_ip", value: (f) => f.host_ip },
                { header: "port", value: (f) => f.port },
                { header: "template_id", value: (f) => f.template_id },
                { header: "name", value: (f) => f.name },
                { header: "severity", value: (f) => f.severity },
                { header: "matched_at", value: (f) => f.matched_at },
                { header: "description", value: (f) => f.description },
                { header: "tags", value: (f) => (f.tags ?? []).join(" ") },
                { header: "triage_state", value: (f) => f.triage_state },
                { header: "triage_note", value: (f) => f.triage_note },
                { header: "triage_review_at", value: (f) => f.triage_review_at },
                { header: "observed_at", value: (f) => f.observed_at },
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
            {query.trim() || severityFilter || triageFilter !== "all"
              ? `${sorted.length} of ${findings.length} shown`
              : `${findings.length} total`}
            {triageBreakdown.map((t) => ` · ${t.count} ${t.label.toLowerCase()}`).join("")}
          </p>
        </>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : findings.length === 0 ? (
        <p className="empty">No web findings yet.</p>
      ) : sorted.length === 0 ? (
        <p className="empty">No findings match the current search/filter.</p>
      ) : (
        <table className="sortable">
          <thead>
            <tr>
              {canEdit && (
                <th className="select-col">
                  <input
                    type="checkbox"
                    title="Select every row currently shown"
                    checked={sorted.length > 0 && sorted.every((f) => selected.has(rowKey(f)))}
                    onChange={(e) => setSelected(e.target.checked ? new Set(sorted.map(rowKey)) : new Set())}
                  />
                </th>
              )}
              <th onClick={() => setSort("host")}>Host{sortIndicator("host")}</th>
              <th onClick={() => setSort("port")}>Port{sortIndicator("port")}</th>
              <th onClick={() => setSort("template_id")}>Template{sortIndicator("template_id")}</th>
              <th onClick={() => setSort("severity")}>Severity{sortIndicator("severity")}</th>
              <th>Matched at</th>
              <th>Description</th>
              <th>Triage</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id}>
                {canEdit && (
                  <td className="select-col">
                    <input type="checkbox" checked={selected.has(rowKey(f))} onChange={() => toggleRow(rowKey(f))} />
                  </td>
                )}
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
                <td>
                  <TriageControl
                    target={{ kind: "nuclei", hostId: f.host_id, templateId: f.template_id, matchedAt: f.matched_at }}
                    state={f.triage_state}
                    note={f.triage_note}
                    reviewAt={f.triage_review_at}
                    expired={f.triage_expired}
                    canEdit={canEdit}
                    onChanged={load}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
