import { type CSSProperties, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, Me, ScannerAgent, SubnetEntry, SubnetsResult } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import TableExport from "../components/TableExport";
import { formatDateTime } from "../lib/formatDate";
import {
  compareSubnets,
  groupIntoSixteens,
  intensity,
  RISK_LABELS,
  RISK_LEVELS,
  riskRank,
  subnetRisk,
  type SubnetRisk,
} from "../lib/subnets";

type View = "map" | "table";
type MapMetric = "risk" | "hosts" | "openPorts";
type SortKey = "subnet" | "hosts" | "openPorts" | "hostsWithCves" | "criticalHosts" | "kevHosts" | "risk" | "lastSeenAt";
type SortDirection = "asc" | "desc";

const PREFIXES = [16, 20, 22, 24];

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
  const [metric, setMetric] = useState<MapMetric>("risk");
  const [prefix, setPrefix] = useState(24);
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

  useEffect(() => {
    setLoading(true);
    setError(null);
    api
      .subnets(effectivePrefix, scannerFilterIds, hideRetired)
      .then(setResult)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load subnets"))
      .finally(() => setLoading(false));
  }, [effectivePrefix, scannerFilterIds, hideRetired]);

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
        </div>
      </div>

      <div className="list-controls">
        {view === "map" ? (
          <div className="filter-chips">
            <span className="empty">Colour by</span>
            {(
              [
                ["risk", "Risk"],
                ["hosts", "Hosts"],
                ["openPorts", "Open ports"],
              ] as [MapMetric, string][]
            ).map(([key, label]) => (
              <button key={key} className={`chip ${metric === key ? "active" : ""}`} onClick={() => setMetric(key)}>
                {label}
              </button>
            ))}
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
            <SubnetMap subnets={subnets} metric={metric} />
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
                        </Link>
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
  if (s.maxCvss !== null) parts.push(`max CVSS ${s.maxCvss}`);
  return parts.join(" · ");
}

// One 16x16 grid per /16, one square per /24 (third octet left to right,
// top to bottom), so where in an address block the hosts actually sit is
// visible - the empty stretches included. IPv6 /64s have no such layout
// and are listed underneath instead.
function SubnetMap({ subnets, metric }: { subnets: SubnetEntry[]; metric: MapMetric }) {
  const { groups, other } = useMemo(() => groupIntoSixteens(subnets), [subnets]);
  const max = Math.max(0, ...subnets.map((s) => (metric === "hosts" ? s.hosts : s.openPorts)));

  function cellStyle(s: SubnetEntry): CSSProperties | undefined {
    if (metric === "risk") return undefined;
    const pct = Math.round(intensity(metric === "hosts" ? s.hosts : s.openPorts, max) * 100);
    return { background: `color-mix(in srgb, var(--chart-series-1) ${pct}%, var(--panel))` };
  }

  function cellClass(s: SubnetEntry): string {
    return metric === "risk" ? `subnet-cell subnet-risk-${subnetRisk(s)}` : "subnet-cell";
  }

  return (
    <>
      <MapLegend metric={metric} max={max} />
      <div className="subnet-map-groups">
        {groups.map((g) => {
          const [a, b] = g.parent.split(".");
          return (
            <section key={g.parent} className="subnet-map-card">
              <h3>
                {g.parent}
                <span className="host-meta">
                  {" "}
                  · {g.subnets} subnet{g.subnets === 1 ? "" : "s"} · {g.hosts} host{g.hosts === 1 ? "" : "s"}
                </span>
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

function MapLegend({ metric, max }: { metric: MapMetric; max: number }) {
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
        {metric === "hosts" ? "Hosts per /24" : "Open ports per /24"}: 1
        <span className="subnet-legend-ramp" aria-hidden="true" />
        {max.toLocaleString()}
      </span>
      <span className="subnet-legend-item">
        <span className="subnet-cell subnet-cell-empty" aria-hidden="true" />
        No known hosts
      </span>
    </div>
  );
}
