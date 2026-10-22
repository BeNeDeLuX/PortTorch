import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, Me, PatchPriorityHost } from "../api";
import SearchInput from "../components/SearchInput";
import PageHeader from "../components/PageHeader";
import TableExport from "../components/TableExport";
import TablePager, { pageSlice } from "../components/TablePager";
import { LIFECYCLE_CAVEAT } from "../lib/softwareLifecycle";
import { rankHosts, type PriorityReason } from "../lib/patchPriority";
import { uptimeLabel } from "../lib/uptime";

// "What do we patch first?" in one list: every host carrying a reason to
// be patched, ranked by lib/patchPriority.ts, with each reason spelled
// out so the order explains itself.

const REASON_CLASS: Record<PriorityReason["kind"], string> = {
  kev: "kev-badge",
  cvss: "cve-badge cve-high",
  eol: "stale-badge",
  eol_soon: "chip-inline",
  uptime: "stale-badge",
  behind_fleet: "chip-inline",
};

export default function PatchPriority({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [hosts, setHosts] = useState<PatchPriorityHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    api
      .patchPriority()
      .then((r) => setHosts(r.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load"))
      .finally(() => setLoading(false));
  }, []);

  const ranked = useMemo(() => rankHosts(hosts), [hosts]);
  const q = query.trim().toLowerCase();
  const shown = q
    ? ranked.filter((h) => h.ip.includes(q) || (h.hostname ?? "").toLowerCase().includes(q) || h.reasons.some((r) => r.label.toLowerCase().includes(q)))
    : ranked;
  const count = (kind: PriorityReason["kind"]) => ranked.filter((h) => h.reasons.some((r) => r.kind === kind)).length;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />
      <h2>Patch Priority</h2>
      <p className="host-meta">
        Every host with a reason to be patched, worst first. A CVE confirmed exploited in the wild (CISA KEV) outranks
        any severity, severity outranks age, and a long uptime or a version behind the rest of the fleet adds weight
        without putting a host above anything actually exposed. CVEs follow the triage policy of the host list: a false
        positive or a fixed finding does not count, an accepted risk still does. {LIFECYCLE_CAVEAT}
      </p>

      {error && <p className="error">{error}</p>}
      {loading ? (
        <p>Loading...</p>
      ) : ranked.length === 0 ? (
        <p className="empty">Nothing to patch that PortTorch can see: no known CVEs, nothing past end of life, no long uptimes.</p>
      ) : (
        <>
          <div className="summary-cards">
            <div className="summary-card">
              <span className="summary-card-value">{ranked.length}</span>
              <span className="summary-card-label">hosts to look at</span>
            </div>
            <div className={`summary-card${count("kev") > 0 ? " summary-card-warn" : ""}`}>
              <span className="summary-card-value">{count("kev")}</span>
              <span className="summary-card-label">with a known exploited CVE</span>
            </div>
            <div className="summary-card">
              <span className="summary-card-value">{count("eol")}</span>
              <span className="summary-card-label">running end-of-life software</span>
            </div>
            <div className="summary-card">
              <span className="summary-card-value">{count("uptime")}</span>
              <span className="summary-card-label">up longer than 180 days</span>
            </div>
            <div className="summary-card">
              <span className="summary-card-value">{count("behind_fleet")}</span>
              <span className="summary-card-label">behind the fleet's newest version</span>
            </div>
          </div>

          <div className="list-controls">
            <form className="search-bar" onSubmit={(e) => e.preventDefault()}>
              <SearchInput
                placeholder="Search by address, name or reason..."
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
              />
            </form>
            <TableExport
              rows={shown}
              filenameBase="porttorch-patch-priority"
              columns={[
                { header: "rank", value: (h) => ranked.indexOf(h) + 1 },
                { header: "ip", value: (h) => h.ip },
                { header: "hostname", value: (h) => h.hostname },
                { header: "scanner", value: (h) => h.scanner },
                { header: "score", value: (h) => h.score },
                { header: "reasons", value: (h) => h.reasons.map((r) => r.label).join("; ") },
                { header: "boot_time", value: (h) => h.bootTime },
                { header: "cve_count", value: (h) => h.cveCount },
                { header: "max_cvss", value: (h) => h.maxCvss },
                { header: "kev", value: (h) => h.kevIds.join(" ") },
              ]}
            />
          </div>

          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Host</th>
                  <th>Score</th>
                  <th>Why</th>
                  <th>Uptime</th>
                  <th>Scanner</th>
                </tr>
              </thead>
              <tbody>
                {pageSlice(shown, page).map((h) => (
                  <tr key={h.id}>
                    <td>{ranked.indexOf(h) + 1}</td>
                    <td>
                      <Link to={`/hosts/${h.id}`}>{h.ip}</Link>
                      {h.hostname && <div className="host-meta">{h.hostname}</div>}
                    </td>
                    <td>{h.score}</td>
                    <td>
                      <div className="source-badges">
                        {h.reasons.map((r) => (
                          <span key={r.kind} className={REASON_CLASS[r.kind]} title={`${r.points} points`}>
                            {r.label}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>{uptimeLabel(h.bootTime) ?? <span className="host-meta">-</span>}</td>
                    <td>{h.scanner ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <TablePager page={page} total={shown.length} onPage={setPage} />
        </>
      )}
    </div>
  );
}
