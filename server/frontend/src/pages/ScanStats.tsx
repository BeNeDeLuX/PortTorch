import { useEffect, useState } from "react";
import { api, Me, ScannerAgent, ScanStatsResult, StatSlice } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import DonutChart from "../components/DonutChart";
import BarChart from "../components/BarChart";

// The composition counterpart to Trends (the other page in the Statistics
// menu): Trends plots how the fleet changed day by day, this one breaks
// down what it currently consists of. Deliberately reads current state
// (newest observation per host+port) rather than Trends' per-day "seen
// open that day" counters, so the two pages' "open ports" numbers answer
// different questions and are not expected to match - the page says so
// itself rather than leaving that as a trap.
export default function ScanStats({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [stats, setStats] = useState<ScanStatsResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);
  const [hideRetired, setHideRetired] = useState(false);
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    api.agents().then(setAgents);
  }, []);

  useEffect(() => {
    setLoading(true);
    api
      .scanStats(scannerFilterIds, hideRetired)
      .then(setStats)
      .finally(() => setLoading(false));
  }, [scannerFilterIds, hideRetired]);

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

      {loading || !stats ? (
        <p>Loading...</p>
      ) : (
        <>
          <div className="stat-tiles">
            <StatTile label="Hosts" value={stats.totals.hosts} />
            <StatTile label="Open ports" value={stats.totals.openPorts} />
            <StatTile label="Distinct ports" value={stats.totals.distinctPorts} />
            <StatTile label="Distinct services" value={stats.totals.distinctServices} />
            <StatTile label="TLS certificates" value={stats.totals.certificates} />
            <StatTile label="Self-signed" value={stats.totals.selfSigned} />
            <StatTile label="Expired / expiring ≤ 30d" value={stats.totals.expiringSoon} />
          </div>

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

function StatTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-value">{value.toLocaleString()}</div>
      <div className="stat-tile-label">{label}</div>
    </div>
  );
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
