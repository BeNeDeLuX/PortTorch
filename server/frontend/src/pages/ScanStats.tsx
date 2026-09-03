import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, Me, ScannerAgent, ScanStatsResult, SecurityStatsResult, StatSlice } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import DonutChart from "../components/DonutChart";
import BarChart from "../components/BarChart";
import TableExport from "../components/TableExport";

// The composition counterpart to Trends (the other page in the Statistics
// menu): Trends plots how the fleet changed day by day, this one breaks
// down what it currently consists of. Deliberately reads current state
// (newest observation per host+port) rather than Trends' per-day "seen
// open that day" counters, so the two pages' "open ports" numbers answer
// different questions and are not expected to match - the page says so
// itself rather than leaving that as a trap.
export default function ScanStats({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [stats, setStats] = useState<ScanStatsResult | null>(null);
  const [security, setSecurity] = useState<SecurityStatsResult | null>(null);
  const [loading, setLoading] = useState(true);
  // Tracked separately from `loading`, so the composition charts appear as
  // soon as they are ready instead of waiting on the much heavier CVE
  // query behind the security ones (see the /security route's own note).
  const [securityLoading, setSecurityLoading] = useState(true);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);
  const [hideRetired, setHideRetired] = useState(false);
  const [compareDays, setCompareDays] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    api.agents().then(setAgents);
  }, []);

  useEffect(() => {
    setLoading(true);
    api
      .scanStats(scannerFilterIds, hideRetired, compareDays)
      .then(setStats)
      .finally(() => setLoading(false));
    setSecurityLoading(true);
    api
      .scanStatsSecurity(scannerFilterIds, hideRetired)
      .then(setSecurity)
      .finally(() => setSecurityLoading(false));
  }, [scannerFilterIds, hideRetired, compareDays]);

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Scan Stats</h2>
      <p className="empty">
        What the fleet currently looks like, counted from the most recent observation of every host and port - a port
        that has since been found closed is not counted here. Trends, beside this page, plots activity per day instead,
        so its numbers answer a different question and won't match these.
      </p>

      <div className="list-controls">
        <div className="list-controls-filters">
          <label className="hide-empty-toggle">
            Scanner
            <ScannerMultiSelect agents={agents} selectedIds={scannerFilterIds} onChange={setScannerFilterIds} align="left" />
          </label>
          <label className="hide-empty-toggle">
            <input type="checkbox" checked={hideRetired} onChange={(e) => setHideRetired(e.target.checked)} />
            Hide retired hosts
          </label>
        </div>
        <div className="view-toggle">
          <button className={!showTable ? "active" : ""} onClick={() => setShowTable(false)}>
            Chart
          </button>
          <button className={showTable ? "active" : ""} onClick={() => setShowTable(true)}>
            Table
          </button>
        </div>
      </div>

      <div className="list-controls">
        <div className="filter-chips">
          <span className="empty">Compare with</span>
          <button className={`chip ${compareDays === null ? "active" : ""}`} onClick={() => setCompareDays(null)}>
            Off
          </button>
          {[7, 30, 90].map((d) => (
            <button key={d} className={`chip ${compareDays === d ? "active" : ""}`} onClick={() => setCompareDays(d)}>
              {d} days ago
            </button>
          ))}
        </div>
        {stats && (
          <TableExport
            rows={exportRows(stats, security)}
            filenameBase="porttorch-scan-stats"
            columns={[
              { header: "chart", value: (r) => r.chart },
              { header: "label", value: (r) => r.label },
              { header: "value", value: (r) => String(r.value) },
            ]}
            jsonRows={() => ({ stats, security })}
          />
        )}
      </div>

      {loading || !stats ? (
        <p>Loading...</p>
      ) : (
        <>
          <div className="stat-tiles">
            <StatTile label="Hosts" value={stats.totals.hosts} previous={stats.comparison?.hosts} />
            <StatTile label="Open ports" value={stats.totals.openPorts} previous={stats.comparison?.openPorts} />
            <StatTile label="Distinct ports" value={stats.totals.distinctPorts} />
            <StatTile label="Distinct services" value={stats.totals.distinctServices} />
            <StatTile label="TLS certificates" value={stats.totals.certificates} previous={stats.comparison?.certificates} />
            <StatTile label="Self-signed" value={stats.totals.selfSigned} />
            <StatTile label="Expired / expiring ≤ 30d" value={stats.totals.expiringSoon} />
          </div>
          {stats.comparison && (
            <p className="empty">
              Change is measured against the state as of {new Date(stats.comparison.since).toLocaleDateString()},
              reconstructed from the observations still on record - a host deleted since (by retention, or by hand)
              cannot be counted, so this is what is still known about that date rather than a snapshot taken on it.
            </p>
          )}

          <section>
            <h2>Per scanner</h2>
            <div className="chart-grid">
              <ChartCard title="Hosts">
                {showTable ? (
                  <SliceTable slices={stats.perScanner.map((s) => ({ label: s.name, value: s.hosts }))} valueLabel="Hosts" />
                ) : (
                  <BarChart items={stats.perScanner.map((s) => ({ label: s.name, value: s.hosts }))} color="var(--chart-cat-1)" />
                )}
              </ChartCard>
              <ChartCard title="Open ports">
                {showTable ? (
                  <SliceTable slices={stats.perScanner.map((s) => ({ label: s.name, value: s.openPorts }))} valueLabel="Open ports" />
                ) : (
                  <BarChart items={stats.perScanner.map((s) => ({ label: s.name, value: s.openPorts }))} color="var(--chart-cat-2)" />
                )}
              </ChartCard>
              <ChartCard title="TLS certificates">
                {showTable ? (
                  <SliceTable slices={stats.perScanner.map((s) => ({ label: s.name, value: s.certificates }))} valueLabel="Certificates" />
                ) : (
                  <BarChart items={stats.perScanner.map((s) => ({ label: s.name, value: s.certificates }))} color="var(--chart-cat-3)" />
                )}
              </ChartCard>
            </div>
          </section>

          <section>
            <h2>Ports and services</h2>
            <div className="chart-grid">
              <ChartCard title="Open ports by port number" hint="Top 10, everything else folded into Other">
                <SliceView slices={stats.topPorts} showTable={showTable} unit="open ports" />
              </ChartCard>
              <ChartCard title="Port types" hint="Well-known ports grouped by what they are for">
                <SliceView slices={stats.portCategories} showTable={showTable} unit="open ports" />
              </ChartCard>
              <ChartCard title="Protocols">
                <SliceView slices={stats.protocols} showTable={showTable} unit="open ports" />
              </ChartCard>
              <ChartCard title="Services" hint="As fingerprinted by nmap; unknown means it could not tell">
                <SliceView slices={stats.services} showTable={showTable} unit="open ports" />
              </ChartCard>
            </div>
          </section>

          <section>
            <h2>Security findings</h2>
            {securityLoading || !security ? (
              <p>Loading...</p>
            ) : security.totals.cveFindings === 0 && security.totals.webFindings === 0 ? (
              <p className="empty">
                No open findings for this filter. A finding appears here once a scan detects a product version that
                matches a cached CVE, or nuclei matches a template - findings dismissed as a false positive or marked
                fixed are left out, while an accepted risk still counts, since the host is still exposed.
              </p>
            ) : (
              <>
                <div className="stat-tiles">
                  <StatTile label="CVE findings" value={security.totals.cveFindings} />
                  <StatTile label="Affected hosts" value={security.totals.affectedHosts} />
                  <StatTile label="Known exploited (KEV)" value={security.totals.kevFindings} />
                  <StatTile label="Hosts with a KEV" value={security.totals.kevHosts} />
                  <StatTile label="Used by ransomware" value={security.totals.ransomwareCves} />
                  <StatTile label="Web findings" value={security.totals.webFindings} />
                </div>
                <div className="chart-grid">
                  <ChartCard title="CVE severity" hint="One finding per host and CVE, not per port">
                    <SliceView slices={security.cveSeverities} showTable={showTable} unit="findings" colors={CVSS_COLORS} />
                  </ChartCard>
                  <ChartCard title="Exploit probability (EPSS)" hint="Predicted chance of exploitation in the next 30 days">
                    <SliceView slices={security.epssBuckets} showTable={showTable} unit="findings" colors={EPSS_COLORS} />
                  </ChartCard>
                  <ChartCard title="Web finding severity" hint="nuclei template matches, newest per host and match">
                    <SliceView slices={security.nucleiSeverities} showTable={showTable} unit="findings" colors={NUCLEI_COLORS} />
                  </ChartCard>
                </div>
                {security.topHosts.length > 0 && (
                  <>
                    <h3>Most exposed hosts</h3>
                    <p className="empty">
                      Ordered the way the Vulnerabilities page orders findings: confirmed-exploited (KEV) first, then
                      highest CVSS, then sheer count.
                    </p>
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Host</th>
                            <th>CVEs</th>
                            <th>Highest CVSS</th>
                            <th>KEV</th>
                            <th>Web findings</th>
                          </tr>
                        </thead>
                        <tbody>
                          {security.topHosts.map((h) => (
                            <tr key={h.hostId}>
                              <td>
                                <Link to={`/hosts/${h.hostId}`}>{h.hostname ? `${h.ip} (${h.hostname})` : h.ip}</Link>
                              </td>
                              <td>{h.cveCount.toLocaleString()}</td>
                              <td>{h.maxCvss === null ? "-" : h.maxCvss.toFixed(1)}</td>
                              <td>{h.kevCount > 0 ? <span className="kev-badge">{h.kevCount}</span> : "-"}</td>
                              <td>{h.webFindings.toLocaleString()}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </>
            )}
          </section>

          <section>
            <h2>Hosts</h2>
            <div className="chart-grid">
              <ChartCard
                title="Operating system"
                hint="From nmap's -O fingerprinting, which needs a scanner running as root or via install.sh's sudo wrapper"
              >
                <SliceView slices={stats.osFamilies} showTable={showTable} unit="hosts" />
              </ChartCard>
              <ChartCard title="Device type" hint="nmap's own classification: general purpose, router, printer, ...">
                <SliceView slices={stats.deviceTypes} showTable={showTable} unit="hosts" />
              </ChartCard>
              <ChartCard title="Tags" hint="Service auto-tags plus manual ones - a host can carry several, so these add up to more than the host count">
                <SliceView slices={stats.tags} showTable={showTable} unit="tagged hosts" />
              </ChartCard>
            </div>
          </section>

          <section>
            <h2>Scanning</h2>
            <p className="empty">
              Completed scans over the last {stats.performanceWindowDays} days. Durations come from completed scans
              only - a cancelled scan says how long someone let it run, and a failed one is usually fast for the wrong
              reason, so averaging either in would make a scanner look faster the more often it breaks.
            </p>
            {stats.scanPerformance.length === 0 ? (
              <p className="empty">No scan finished in this window.</p>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Scanner</th>
                      <th>Scans</th>
                      <th>Completed</th>
                      <th>Failed</th>
                      <th>Cancelled</th>
                      <th>Median</th>
                      <th>Average</th>
                      <th>Longest</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.scanPerformance.map((p) => (
                      <tr key={p.id ?? "deleted"}>
                        <td>{p.name}</td>
                        <td>{p.scans.toLocaleString()}</td>
                        <td>{p.completed.toLocaleString()}</td>
                        <td>{p.failed > 0 ? <span className="cve-badge cve-high">{p.failed}</span> : "-"}</td>
                        <td>{p.cancelled > 0 ? p.cancelled.toLocaleString() : "-"}</td>
                        <td>{formatDuration(p.medianDurationMs)}</td>
                        <td>{formatDuration(p.avgDurationMs)}</td>
                        <td>{formatDuration(p.maxDurationMs)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section>
            <h2>Most exposed</h2>
            <div className="chart-grid">
              <ChartCard title="Hosts with the most open ports">
                {stats.topHostsByPorts.length === 0 ? (
                  <p className="empty">Nothing scanned yet for this filter.</p>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Host</th>
                          <th>Open ports</th>
                        </tr>
                      </thead>
                      <tbody>
                        {stats.topHostsByPorts.map((h) => (
                          <tr key={h.hostId}>
                            <td>
                              <Link to={`/hosts/${h.hostId}`}>{h.hostname ? `${h.ip} (${h.hostname})` : h.ip}</Link>
                            </td>
                            <td>{h.openPorts.toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </ChartCard>
              <ChartCard title="Subnets with the most open ports" hint="Grouped by /24; IPv6 hosts are not bucketed">
                {stats.topSubnets.length === 0 ? (
                  <p className="empty">No IPv4 hosts for this filter.</p>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Subnet</th>
                          <th>Hosts</th>
                          <th>Open ports</th>
                        </tr>
                      </thead>
                      <tbody>
                        {stats.topSubnets.map((n) => (
                          <tr key={n.subnet}>
                            <td>{n.subnet}</td>
                            <td>{n.hosts.toLocaleString()}</td>
                            <td>{n.openPorts.toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </ChartCard>
            </div>
          </section>

          <section>
            <h2>TLS certificates</h2>
            <div className="chart-grid">
              <ChartCard title="Issuance">
                <SliceView slices={stats.certIssuance} showTable={showTable} unit="certificates" />
              </ChartCard>
              <ChartCard title="Expiry">
                <SliceView slices={stats.certExpiry} showTable={showTable} unit="certificates" colors={EXPIRY_COLORS} />
              </ChartCard>
              <ChartCard title="TLS version">
                <SliceView slices={stats.tlsVersions} showTable={showTable} unit="certificates" />
              </ChartCard>
              <ChartCard title="Key algorithm">
                <SliceView slices={stats.certKeys} showTable={showTable} unit="certificates" />
              </ChartCard>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function StatTile({ label, value, previous }: { label: string; value: number; previous?: number }) {
  // No delta shown when nothing changed - a row of "+0" chips reads as
  // noise and buries the two numbers that did move.
  const delta = previous === undefined ? null : value - previous;
  return (
    <div className="stat-tile">
      <div className="stat-tile-value">
        {value.toLocaleString()}
        {delta !== null && delta !== 0 && (
          <span className={`stat-delta ${delta > 0 ? "up" : "down"}`}>
            {delta > 0 ? "+" : ""}
            {delta.toLocaleString()}
          </span>
        )}
      </div>
      <div className="stat-tile-label">{label}</div>
    </div>
  );
}

// Durations are minutes-to-hours here, so seconds are noise above a
// minute and a bare millisecond count is unreadable at any size.
function formatDuration(ms: number | null): string {
  if (ms === null) return "-";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

// Every chart on the page flattened into one long "chart, label, value"
// table - the honest CSV shape for a page that is a dozen small
// distributions rather than one table. The JSON export keeps the nested
// payload as it arrived instead, since that shape is already the API's.
function exportRows(stats: ScanStatsResult, security: SecurityStatsResult | null) {
  const rows: Array<{ chart: string; label: string; value: number }> = [];
  const add = (chart: string, slices: StatSlice[]) => {
    for (const s of slices) rows.push({ chart, label: s.label, value: s.value });
  };
  for (const [label, value] of Object.entries(stats.totals)) rows.push({ chart: "Totals", label, value });
  for (const s of stats.perScanner) {
    rows.push({ chart: "Per scanner - hosts", label: s.name, value: s.hosts });
    rows.push({ chart: "Per scanner - open ports", label: s.name, value: s.openPorts });
    rows.push({ chart: "Per scanner - certificates", label: s.name, value: s.certificates });
  }
  add("Open ports by port number", stats.topPorts);
  add("Port types", stats.portCategories);
  add("Protocols", stats.protocols);
  add("Services", stats.services);
  add("Operating system", stats.osFamilies);
  add("Device type", stats.deviceTypes);
  add("Tags", stats.tags);
  add("Certificate issuance", stats.certIssuance);
  add("Certificate expiry", stats.certExpiry);
  add("TLS version", stats.tlsVersions);
  add("Key algorithm", stats.certKeys);
  for (const h of stats.topHostsByPorts) rows.push({ chart: "Hosts with the most open ports", label: h.ip, value: h.openPorts });
  for (const n of stats.topSubnets) rows.push({ chart: "Subnets with the most open ports", label: n.subnet, value: n.openPorts });
  if (security) {
    for (const [label, value] of Object.entries(security.totals)) rows.push({ chart: "Security totals", label, value });
    add("CVE severity", security.cveSeverities);
    add("Exploit probability (EPSS)", security.epssBuckets);
    add("Web finding severity", security.nucleiSeverities);
    for (const h of security.topHosts) rows.push({ chart: "Most exposed hosts", label: h.ip, value: h.cveCount });
  }
  return rows;
}

function ChartCard({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="chart-card">
      <h3>{title}</h3>
      {hint && <p className="chart-card-hint">{hint}</p>}
      {children}
    </div>
  );
}

function SliceView({
  slices,
  showTable,
  unit,
  colors,
}: {
  slices: StatSlice[];
  showTable: boolean;
  unit: string;
  colors?: Record<string, string>;
}) {
  return showTable ? (
    <SliceTable slices={slices} valueLabel="Count" />
  ) : (
    <DonutChart slices={slices} unit={unit} colors={colors} />
  );
}

// Certificate expiry is the one chart here whose slices are ordered by
// how bad they are, so it gets the status colors the rest of the app
// already uses for exactly that, instead of arbitrary categorical slots.
// Severity, exploit probability and expiry are the charts whose slices
// have a real order from bad to fine, so they use the status colours the
// rest of the app already uses for exactly that rather than arbitrary
// categorical slots. CVSS severity reuses the .cve-* palette's own
// meaning, so a "Critical" slice here reads as the same thing as a
// Critical badge on the Vulnerabilities page.
const CVSS_COLORS: Record<string, string> = {
  Critical: "var(--danger)",
  High: "var(--chart-cat-2)",
  Medium: "var(--warning)",
  Low: "var(--chart-cat-3)",
  Unknown: "var(--chart-cat-8)",
};

const EPSS_COLORS: Record<string, string> = {
  "≥ 50%": "var(--danger)",
  "10-50%": "var(--chart-cat-2)",
  "1-10%": "var(--warning)",
  "< 1%": "var(--chart-cat-3)",
  "No score yet": "var(--chart-cat-8)",
};

const NUCLEI_COLORS: Record<string, string> = {
  Critical: "var(--danger)",
  High: "var(--chart-cat-2)",
  Medium: "var(--warning)",
  Low: "var(--chart-cat-3)",
  Info: "var(--chart-cat-1)",
  Unknown: "var(--chart-cat-8)",
};

const EXPIRY_COLORS: Record<string, string> = {
  Expired: "var(--danger)",
  "≤ 30 days": "var(--warning)",
  "31-90 days": "var(--chart-cat-4)",
  "> 90 days": "var(--success)",
};

// The table view is the relief valve for the chart's color-coded slices -
// same role the Trends page's own Chart/Table toggle plays.
function SliceTable({ slices, valueLabel }: { slices: StatSlice[]; valueLabel: string }) {
  const total = slices.reduce((sum, s) => sum + s.value, 0);
  if (total === 0) {
    return <p className="empty">Nothing scanned yet for this filter.</p>;
  }
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>{valueLabel}</th>
            <th>Share</th>
          </tr>
        </thead>
        <tbody>
          {slices.map((s) => (
            <tr key={s.label}>
              <td>{s.label}</td>
              <td>{s.value.toLocaleString()}</td>
              <td>{((s.value / total) * 100).toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
