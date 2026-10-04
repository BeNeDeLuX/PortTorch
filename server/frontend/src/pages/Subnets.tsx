import { type CSSProperties, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, Me, ScannerAgent, SubnetEntry, SubnetsResult } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import SubnetChanges from "../components/SubnetChanges";
import TableExport from "../components/TableExport";
import { formatDateTime } from "../lib/formatDate";
import {
  compareSubnets,
  groupIntoEights,
  groupIntoSixteens,
  intensity,
  matchesNetworkFilter,
  RISK_LABELS,
  RISK_LEVELS,
  riskRank,
  subnetRisk,
  type SixteenGroup,
  type SubnetRisk,
} from "../lib/subnets";

type View = "map" | "table" | "changes";
type MapMetric = "risk" | "hosts" | "openPorts" | "new";
type SortKey =
  | "subnet"
  | "hosts"
  | "openPorts"
  | "hostsWithCves"
  | "criticalHosts"
  | "kevHosts"
  | "newHosts"
  | "risk"
  | "lastSeenAt";
type SortDirection = "asc" | "desc";

const PREFIXES = [16, 20, 22, 24];

const METRIC_KEY = "porttorch.subnets.metric";
const METRICS: MapMetric[] = ["hosts", "openPorts", "new", "risk"];
// Windows for "new hosts", matching the server's allowlist.
const NEW_WINDOWS = [1, 7, 30, 90];

// Hosts by default: "where are my machines" is the question the map is
// opened with, and a risk colouring is mostly grey on a fleet with little
// CVE data. A different choice is remembered per browser.
function storedMetric(): MapMetric {
  try {
    const v = localStorage.getItem(METRIC_KEY);
    return METRICS.includes(v as MapMetric) ? (v as MapMetric) : "hosts";
  } catch {
    return "hosts";
  }
}

// Above this many /16s the map opens with an overview of /8s instead of
// one card per /16, and the cards below are paged.
const OVERVIEW_THRESHOLD = 6;
const CARDS_PER_PAGE = 12;

// Every subnet that holds a known host, and how exposed it is - the one
// question neither the per-host list nor the fleet-wide Scan Stats could
// answer: which network is the problem. A subnet opens the Dashboard
// filtered to exactly its hosts, since the Dashboard's search already
// matches a CIDR.
export default function Subnets({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);
  const [hideRetired, setHideRetired] = useState(false);
  const [view, setView] = useState<View>("map");
  const [metric, setMetricState] = useState<MapMetric>(storedMetric);
  const [prefix, setPrefix] = useState(24);
  const [newDays, setNewDays] = useState(7);
  // The network the Changes view compares, handed over from a map card or
  // a table row.
  const [changesNetwork, setChangesNetwork] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("subnet");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [result, setResult] = useState<SubnetsResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // The map is a grid of /24s by construction, so it always asks for
  // /24; the table is where the grouping can be widened.
  const effectivePrefix = view === "map" ? 24 : prefix;

  useEffect(() => {
    api.agents().then(setAgents);
  }, []);

  function setMetric(m: MapMetric) {
    setMetricState(m);
    try {
      localStorage.setItem(METRIC_KEY, m);
    } catch {
      // Private window or blocked storage: the choice just isn't remembered.
    }
  }

  function openChanges(network: string) {
    setChangesNetwork(network);
    setView("changes");
  }

  useEffect(() => {
    if (view === "changes") return;
    setLoading(true);
    setError(null);
    api
      .subnets(effectivePrefix, scannerFilterIds, hideRetired, newDays)
      .then(setResult)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load subnets"))
      .finally(() => setLoading(false));
  }, [effectivePrefix, scannerFilterIds, hideRetired, view, newDays]);

  const subnets = result?.subnets ?? [];
  const totals = useMemo(
    () => ({
      subnets: subnets.length,
      hosts: subnets.reduce((n, s) => n + s.hosts, 0),
      withKev: subnets.filter((s) => s.kevHosts > 0).length,
      withCritical: subnets.filter((s) => s.criticalHosts > 0).length,
    }),
    [subnets]
  );

  const sorted = useMemo(() => {
    const dir = sortDirection === "asc" ? 1 : -1;
    return [...subnets].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "subnet":
          cmp = compareSubnets(a.subnet, b.subnet);
          break;
        case "risk":
          cmp = riskRank(subnetRisk(a)) - riskRank(subnetRisk(b)) || (b.maxCvss ?? -1) - (a.maxCvss ?? -1);
          break;
        case "lastSeenAt":
          cmp = (a.lastSeenAt ?? "").localeCompare(b.lastSeenAt ?? "");
          break;
        default:
          cmp = a[sortKey] - b[sortKey];
      }
      return cmp * dir || compareSubnets(a.subnet, b.subnet);
    });
  }, [subnets, sortKey, sortDirection]);

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      // Counts read best largest-first; risk is ranked worst-first already.
      setSortDirection(key === "subnet" || key === "risk" ? "asc" : "desc");
    }
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  const maxHosts = Math.max(0, ...subnets.map((s) => s.hosts));

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Subnets</h2>
      <p className="host-meta">
        Every subnet that holds a known host, grouped by address, with how exposed it is. Click one to open the host
        list filtered to it. A range where no host has been found does not appear here - Network Coverage is the page for
        ranges nobody has scanned.
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
          <button className={view === "map" ? "active" : ""} onClick={() => setView("map")}>
            Map
          </button>
          <button className={view === "table" ? "active" : ""} onClick={() => setView("table")}>
            Table
          </button>
          <button className={view === "changes" ? "active" : ""} onClick={() => setView("changes")}>
            Changes
          </button>
        </div>
      </div>

      {view === "changes" ? (
        <SubnetChanges me={me} network={changesNetwork} scannerAgentIds={scannerFilterIds} hideRetired={hideRetired} />
      ) : (
        <>
          <div className="list-controls">
            {view === "map" ? (
              <div className="filter-chips">
                <span className="empty">Colour by</span>
                {(
                  [
                    ["hosts", "Hosts"],
                    ["openPorts", "Open ports"],
                    ["new", "New hosts"],
                    ["risk", "Risk"],
                  ] as [MapMetric, string][]
                ).map(([key, label]) => (
                  <button key={key} className={`chip ${metric === key ? "active" : ""}`} onClick={() => setMetric(key)}>
                    {label}
                  </button>
                ))}
                {metric === "new" && (
                  <>
                    <span className="empty">first seen in the last</span>
                    {NEW_WINDOWS.map((d) => (
                      <button key={d} className={`chip ${newDays === d ? "active" : ""}`} onClick={() => setNewDays(d)}>
                        {d === 1 ? "24 hours" : `${d} days`}
                      </button>
                    ))}
                  </>
                )}
              </div>
            ) : (
              <div className="filter-chips">
                <span className="empty">Group IPv4 by</span>
                {PREFIXES.map((p) => (
                  <button key={p} className={`chip ${prefix === p ? "active" : ""}`} onClick={() => setPrefix(p)}>
                    /{p}
                  </button>
                ))}
              </div>
            )}
            {view === "table" && result && (
              <TableExport
                rows={sorted}
                filenameBase={`porttorch-subnets-${effectivePrefix}`}
                columns={[
                  { header: "subnet", value: (s) => s.subnet },
                  { header: "hosts", value: (s) => s.hosts },
                  { header: "open_ports", value: (s) => s.openPorts },
                  { header: "hosts_with_cves", value: (s) => s.hostsWithCves },
                  { header: "critical_hosts", value: (s) => s.criticalHosts },
                  { header: "kev_hosts", value: (s) => s.kevHosts },
                  { header: `new_hosts_${newDays}d`, value: (s) => s.newHosts },
                  { header: "max_cvss", value: (s) => s.maxCvss },
                  { header: "last_seen_at", value: (s) => s.lastSeenAt },
                ]}
              />
            )}
          </div>

          {error && <p className="callout-danger">{error}</p>}

          {loading && !result ? (
            <p>Loading...</p>
          ) : subnets.length === 0 ? (
            <p className="empty">No hosts match the current filter.</p>
          ) : (
            <>
              <div className="stat-tiles">
                <Tile label="Subnets" value={totals.subnets} />
                <Tile label="Hosts" value={totals.hosts} />
                <Tile label="Subnets with a KEV finding" value={totals.withKev} />
                <Tile label="Subnets with a critical CVE" value={totals.withCritical} />
              </div>
              {view === "map" ? (
                <SubnetMap subnets={subnets} metric={metric} newDays={result?.newDays ?? newDays} onCompare={openChanges} />
              ) : (
                <div className="table-scroll">
                  <table className="sortable">
                    <thead>
                      <tr>
                        <th onClick={() => setSort("subnet")}>Subnet{sortIndicator("subnet")}</th>
                        <th onClick={() => setSort("hosts")}>Hosts{sortIndicator("hosts")}</th>
                        <th onClick={() => setSort("openPorts")}>Open ports{sortIndicator("openPorts")}</th>
                        <th onClick={() => setSort("hostsWithCves")}>Hosts with CVEs{sortIndicator("hostsWithCves")}</th>
                        <th onClick={() => setSort("criticalHosts")}>Critical hosts{sortIndicator("criticalHosts")}</th>
                        <th onClick={() => setSort("kevHosts")}>KEV hosts{sortIndicator("kevHosts")}</th>
                        <th onClick={() => setSort("newHosts")} title={`First seen in the last ${newDays === 1 ? "24 hours" : `${newDays} days`}`}>
                          New{sortIndicator("newHosts")}
                        </th>
                        <th onClick={() => setSort("risk")}>Risk{sortIndicator("risk")}</th>
                        <th onClick={() => setSort("lastSeenAt")}>Last seen{sortIndicator("lastSeenAt")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sorted.map((s) => (
                        <tr key={s.subnet}>
                          <td>
                            <Link className="port-link" to={`/?q=${encodeURIComponent(s.subnet)}`}>
                              {s.subnet}
                            </Link>{" "}
                            <button type="button" className="link-button subnet-changes-link" onClick={() => openChanges(s.subnet)}>
                              changes
                            </button>
                          </td>
                          <td>
                            <div className="subnet-bar-cell">
                              <span>{s.hosts.toLocaleString()}</span>
                              <span className="subnet-bar" aria-hidden="true">
                                <span style={{ width: `${maxHosts ? (s.hosts / maxHosts) * 100 : 0}%` }} />
                              </span>
                            </div>
                          </td>
                          <td>{s.openPorts.toLocaleString()}</td>
                          <td>{s.hostsWithCves.toLocaleString()}</td>
                          <td>{s.criticalHosts.toLocaleString()}</td>
                          <td>{s.kevHosts.toLocaleString()}</td>
                          <td>{s.newHosts > 0 ? s.newHosts.toLocaleString() : <span className="host-meta">-</span>}</td>
                          <td>
                            <RiskBadge subnet={s} />
                          </td>
                          <td>{s.lastSeenAt ? formatDateTime(s.lastSeenAt, me.preferences) : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function Tile({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-value">{value.toLocaleString()}</div>
      <div className="stat-tile-label">{label}</div>
    </div>
  );
}

function RiskBadge({ subnet }: { subnet: SubnetEntry }) {
  const risk = subnetRisk(subnet);
  if (risk === "none") return <span className="host-meta">-</span>;
  if (risk === "kev") return <span className="kev-badge" title={RISK_LABELS.kev}>KEV</span>;
  return (
    <span className={`cve-badge cve-${risk}`} title={RISK_LABELS[risk]}>
      {subnet.maxCvss !== null ? `CVSS ${subnet.maxCvss}` : risk}
    </span>
  );
}

function describe(s: SubnetEntry): string {
  const parts = [
    s.subnet,
    `${s.hosts} host${s.hosts === 1 ? "" : "s"}`,
    `${s.openPorts} open port${s.openPorts === 1 ? "" : "s"}`,
  ];
  if (s.hostsWithCves > 0) parts.push(`${s.hostsWithCves} with CVEs`);
  if (s.kevHosts > 0) parts.push(`${s.kevHosts} with a KEV finding`);
  if (s.newHosts > 0) parts.push(`${s.newHosts} new`);
  if (s.maxCvss !== null) parts.push(`max CVSS ${s.maxCvss}`);
  return parts.join(" · ");
}

type NetworkSort = "address" | "hosts" | "risk";

function metricValue(x: { hosts: number; openPorts: number; newHosts: number }, metric: MapMetric): number {
  return metric === "openPorts" ? x.openPorts : metric === "new" ? x.newHosts : x.hosts;
}

const METRIC_UNIT: Record<Exclude<MapMetric, "risk">, string> = {
  hosts: "hosts",
  openPorts: "open ports",
  new: "new hosts",
};

function describeNetwork(g: SixteenGroup): string {
  const parts = [
    g.parent,
    `${g.subnets} /24${g.subnets === 1 ? "" : "s"}`,
    `${g.hosts} host${g.hosts === 1 ? "" : "s"}`,
    `${g.openPorts} open port${g.openPorts === 1 ? "" : "s"}`,
  ];
  if (g.kevHosts > 0) parts.push(`${g.kevHosts} with a KEV finding`);
  if (g.maxCvss !== null) parts.push(`max CVSS ${g.maxCvss}`);
  return parts.join(" · ");
}

// One 16x16 grid per /16, one square per /24 (third octet left to right,
// top to bottom), so where in an address block the hosts actually sit is
// visible - the empty stretches included. IPv6 /64s have no such layout
// and are listed underneath instead.
//
// A fleet spread over many /16s gets one level more: an overview with one
// 16x16 grid per /8 and one square per /16, the same layout one octet up.
// Clicking a square narrows the cards to that /16; the cards can also be
// filtered by typing a prefix, sorted, and are paged rather than all
// rendered at once.
function SubnetMap({
  subnets,
  metric,
  newDays,
  onCompare,
}: {
  subnets: SubnetEntry[];
  metric: MapMetric;
  newDays: number;
  onCompare: (network: string) => void;
}) {
  const { groups, other } = useMemo(() => groupIntoSixteens(subnets), [subnets]);
  const eights = useMemo(() => groupIntoEights(groups), [groups]);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<NetworkSort>("address");
  const [shown, setShown] = useState(CARDS_PER_PAGE);

  const max = Math.max(0, ...subnets.map((s) => metricValue(s, metric)));
  const maxNetwork = Math.max(0, ...groups.map((g) => metricValue(g, metric)));
  const withOverview = groups.length > OVERVIEW_THRESHOLD;

  const visible = useMemo(() => {
    const matching = groups.filter((g) => matchesNetworkFilter(g.parent, filter));
    if (sort === "hosts") matching.sort((a, b) => b.hosts - a.hosts || compareSubnets(a.parent, b.parent));
    if (sort === "risk")
      matching.sort(
        (a, b) =>
          riskRank(subnetRisk(a)) - riskRank(subnetRisk(b)) ||
          (b.maxCvss ?? -1) - (a.maxCvss ?? -1) ||
          b.hosts - a.hosts
      );
    return matching;
  }, [groups, filter, sort]);

  // A new filter or order starts from the top rather than keeping a page
  // count that belonged to a different list.
  useEffect(() => setShown(CARDS_PER_PAGE), [filter, sort]);

  function fill(value: number, of: number): CSSProperties {
    const pct = Math.round(intensity(value, of) * 100);
    return { background: `color-mix(in srgb, var(--chart-series-1) ${pct}%, var(--panel))` };
  }

  function cellStyle(s: SubnetEntry): CSSProperties | undefined {
    return metric === "risk" ? undefined : fill(metricValue(s, metric), max);
  }

  function cellClass(x: Parameters<typeof subnetRisk>[0]): string {
    return metric === "risk" ? `subnet-cell subnet-risk-${subnetRisk(x)}` : "subnet-cell";
  }

  function focusNetwork(parent: string) {
    setFilter(parent);
    document.getElementById("subnet-network-cards")?.scrollIntoView({ block: "start" });
  }

  const page = visible.slice(0, shown);

  return (
    <>
      <MapLegend metric={metric} max={max} newDays={newDays} />

      {withOverview && (
        <>
          <h3>Overview</h3>
          <p className="host-meta">
            One square per /16
            {metric !== "risk"
              ? `, shaded by its total from 1 to ${maxNetwork.toLocaleString()} ${METRIC_UNIT[metric]} (log scale)`
              : ", coloured by the worst finding in it"}
            . Click one to show only that network below.
          </p>
          <div className="subnet-map-groups">
            {eights.map((e) => {
              const [a] = e.parent.split(".");
              return (
                <section key={e.parent} className="subnet-map-card">
                  <h3>
                    {e.parent}
                    <span className="host-meta">
                      {" "}
                      · {e.networks} /16{e.networks === 1 ? "" : "s"} · {e.hosts.toLocaleString()} host
                      {e.hosts === 1 ? "" : "s"}
                    </span>
                  </h3>
                  <div className="subnet-grid">
                    {e.cells.map((g, i) =>
                      g ? (
                        <button
                          key={i}
                          type="button"
                          className={`${cellClass(g)}${filter === g.parent ? " subnet-cell-selected" : ""}`}
                          style={metric === "risk" ? undefined : fill(metricValue(g, metric), maxNetwork)}
                          title={describeNetwork(g)}
                          aria-label={describeNetwork(g)}
                          aria-pressed={filter === g.parent}
                          onClick={() => focusNetwork(g.parent)}
                        />
                      ) : (
                        <span key={i} className="subnet-cell subnet-cell-empty" title={`${a}.${i}.0.0/16 - no known hosts`} />
                      )
                    )}
                  </div>
                </section>
              );
            })}
          </div>
        </>
      )}

      {groups.length > 0 && (
        <div className="list-controls" id="subnet-network-cards">
          <div className="list-controls-filters">
            {withOverview && <h3 className="subnet-cards-heading">Networks</h3>}
            <input
              type="search"
              className="subnet-filter"
              placeholder="Filter, e.g. 10.46"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              aria-label="Filter networks by prefix"
            />
            <div className="filter-chips">
              <span className="empty">Sort by</span>
              {(
                [
                  ["address", "Address"],
                  ["hosts", "Hosts"],
                  ["risk", "Risk"],
                ] as [NetworkSort, string][]
              ).map(([key, label]) => (
                <button key={key} className={`chip ${sort === key ? "active" : ""}`} onClick={() => setSort(key)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <span className="host-meta">
            {visible.length === groups.length
              ? `${groups.length} network${groups.length === 1 ? "" : "s"}`
              : `${visible.length} of ${groups.length} networks`}
          </span>
        </div>
      )}

      {groups.length > 0 && visible.length === 0 && (
        <p className="empty">
          No /16 matches "{filter}".{" "}
          <button type="button" className="link-button" onClick={() => setFilter("")}>
            Show all
          </button>
        </p>
      )}

      <div className="subnet-map-groups">
        {page.map((g) => {
          const [a, b] = g.parent.split(".");
          return (
            <section key={g.parent} className="subnet-map-card">
              <h3>
                {g.parent}
                <span className="host-meta">
                  {" "}
                  · {g.subnets} subnet{g.subnets === 1 ? "" : "s"} · {g.hosts.toLocaleString()} host
                  {g.hosts === 1 ? "" : "s"}
                </span>{" "}
                <button type="button" className="link-button subnet-changes-link" onClick={() => onCompare(g.parent)}>
                  changes
                </button>
              </h3>
              <div className="subnet-grid">
                {g.cells.map((s, i) =>
                  s ? (
                    <Link
                      key={i}
                      to={`/?q=${encodeURIComponent(s.subnet)}`}
                      className={cellClass(s)}
                      style={cellStyle(s)}
                      title={describe(s)}
                      aria-label={describe(s)}
                    />
                  ) : (
                    <span key={i} className="subnet-cell subnet-cell-empty" title={`${a}.${b}.${i}.0/24 - no known hosts`} />
                  )
                )}
              </div>
            </section>
          );
        })}
      </div>
      {visible.length > shown && (
        <p>
          <button type="button" onClick={() => setShown((n) => n + CARDS_PER_PAGE)}>
            Show {Math.min(CARDS_PER_PAGE, visible.length - shown)} more
          </button>{" "}
          <button type="button" className="link-button" onClick={() => setShown(visible.length)}>
            Show all {visible.length}
          </button>
        </p>
      )}
      {other.length > 0 && (
        <section className="subnet-map-card">
          <h3>
            IPv6
            <span className="host-meta"> · grouped by /64</span>
          </h3>
          <div className="filter-chips">
            {other.map((s) => (
              <Link
                key={s.subnet}
                to={`/?q=${encodeURIComponent(s.subnet)}`}
                className={`chip ${metric === "risk" ? `subnet-chip-risk-${subnetRisk(s)}` : ""}`}
                title={describe(s)}
              >
                {s.subnet} ({s.hosts})
              </Link>
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function MapLegend({ metric, max, newDays }: { metric: MapMetric; max: number; newDays: number }) {
  if (metric === "risk") {
    return (
      <div className="subnet-legend">
        {RISK_LEVELS.map((r: SubnetRisk) => (
          <span key={r} className="subnet-legend-item">
            <span className={`subnet-cell subnet-risk-${r}`} aria-hidden="true" />
            {RISK_LABELS[r]}
          </span>
        ))}
        <span className="subnet-legend-item">
          <span className="subnet-cell subnet-cell-empty" aria-hidden="true" />
          No known hosts
        </span>
      </div>
    );
  }
  return (
    <div className="subnet-legend">
      <span className="subnet-legend-item">
        {metric === "hosts" ? "Hosts per /24" : metric === "openPorts" ? "Open ports per /24" : `Hosts first seen in the last ${newDays === 1 ? "24 hours" : `${newDays} days`}, per /24`}: 1
        <span className="subnet-legend-ramp" aria-hidden="true" />
        {max.toLocaleString()}
        <span title="A few very full networks would otherwise wash every small one out to the same pale shade.">
          (log scale)
        </span>
      </span>
      <span className="subnet-legend-item">
        <span className="subnet-cell subnet-cell-empty" aria-hidden="true" />
        No known hosts
      </span>
    </div>
  );
}
