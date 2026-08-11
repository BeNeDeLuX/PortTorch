import { useEffect, useMemo, useState } from "react";
import { api, Me, ScannerAgent, TrendsResult } from "../api";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";

type SeriesKey = "totalHosts" | "newHosts" | "scans" | "openPorts" | "cveMatches";

interface SeriesDef {
  key: SeriesKey;
  label: string;
  // CSS custom property name (defined in styles.css, themed per light/dark -
  // see the .trend-chart rules) rather than a raw hex, so the chart follows
  // the same light/dark swap every other themed color in this app already
  // uses instead of needing its own media-query handling here.
  color: string;
}

const ACTIVITY_SERIES: SeriesDef[] = [
  { key: "newHosts", label: "New hosts", color: "var(--chart-series-1)" },
  { key: "scans", label: "Scans", color: "var(--chart-series-2)" },
  { key: "openPorts", label: "Open ports seen", color: "var(--chart-series-3)" },
  { key: "cveMatches", label: "CVE matches seen", color: "var(--chart-series-4)" },
];

const DAY_PRESETS = [7, 30, 90, 365];

const VIEW_W = 900;
const VIEW_H = 260;
const PAD_L = 48;
const PAD_R = 16;
const PAD_T = 16;
const PAD_B = 32;

function formatCompact(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, "") + "K";
  return String(n);
}

// Rounds a y-axis max up to a "clean" step (1/2/5 * 10^n) so ticks land on
// round numbers (0/1,000/2,000) rather than whatever the data's actual max
// happens to be - marks-and-anatomy.md's "round to clean numbers" rule.
function niceMax(max: number): number {
  if (max <= 0) return 4;
  const magnitude = Math.pow(10, Math.floor(Math.log10(max)));
  const normalized = max / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

function pathFor(values: number[], xFor: (i: number) => number, yFor: (v: number) => number): string {
  return values.map((v, i) => `${i === 0 ? "M" : "L"} ${xFor(i).toFixed(2)} ${yFor(v).toFixed(2)}`).join(" ");
}

function TrendChart({
  data,
  series,
  formatDateShort,
}: {
  data: TrendsResult["series"];
  series: SeriesDef[];
  formatDateShort: (date: string) => string;
}) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  const n = data.length;
  const xFor = (i: number) => (n <= 1 ? PAD_L : PAD_L + (i / (n - 1)) * (VIEW_W - PAD_L - PAD_R));
  const maxValue = niceMax(Math.max(1, ...series.flatMap((s) => data.map((d) => d[s.key] as number))));
  const yFor = (v: number) => VIEW_T_TO_B(v, maxValue);
  function VIEW_T_TO_B(v: number, max: number) {
    return VIEW_H - PAD_B - (v / max) * (VIEW_H - PAD_T - PAD_B);
  }

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(maxValue * f));

  function handlePointerMove(e: React.PointerEvent<SVGRectElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const relX = ((e.clientX - rect.left) / rect.width) * VIEW_W;
    const frac = n <= 1 ? 0 : (relX - PAD_L) / (VIEW_W - PAD_L - PAD_R);
    const idx = Math.max(0, Math.min(n - 1, Math.round(frac * (n - 1))));
    setHoverIndex(idx);
  }

  const hovered = hoverIndex !== null ? data[hoverIndex] : null;
  // Flip the tooltip to the left of the crosshair once it would otherwise
  // overflow the chart's right edge.
  const tooltipOnRight = hoverIndex !== null && xFor(hoverIndex) < VIEW_W * 0.7;

  return (
    <div className="trend-chart">
      {series.length > 1 && (
        <div className="trend-legend">
          {series.map((s) => (
            <span key={s.key} className="trend-legend-item">
              <span className="trend-legend-swatch" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      )}
      <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} width="100%" height={VIEW_H} role="img" aria-label="Trend chart">
        {yTicks.map((t) => (
          <g key={t}>
            <line x1={PAD_L} x2={VIEW_W - PAD_R} y1={yFor(t)} y2={yFor(t)} className="trend-gridline" />
            <text x={PAD_L - 8} y={yFor(t)} className="trend-axis-label" textAnchor="end" dominantBaseline="middle">
              {formatCompact(t)}
            </text>
          </g>
        ))}
        <line x1={PAD_L} x2={PAD_L} y1={PAD_T} y2={VIEW_H - PAD_B} className="trend-axis" />
        <line x1={PAD_L} x2={VIEW_W - PAD_R} y1={VIEW_H - PAD_B} y2={VIEW_H - PAD_B} className="trend-axis" />

        {n > 0 && (
          <>
            <text x={xFor(0)} y={VIEW_H - PAD_B + 18} className="trend-axis-label" textAnchor="start">
              {formatDateShort(data[0].date)}
            </text>
            <text x={xFor(n - 1)} y={VIEW_H - PAD_B + 18} className="trend-axis-label" textAnchor="end">
              {formatDateShort(data[n - 1].date)}
            </text>
          </>
        )}

        {series.map((s) => {
          const values = data.map((d) => d[s.key] as number);
          const isSingle = series.length === 1;
          return (
            <g key={s.key}>
              {isSingle && n > 1 && (
                <path
                  d={`${pathFor(values, xFor, yFor)} L ${xFor(n - 1)} ${VIEW_H - PAD_B} L ${xFor(0)} ${VIEW_H - PAD_B} Z`}
                  fill={s.color}
                  opacity={0.1}
                  stroke="none"
                />
              )}
              {n > 1 && <path d={pathFor(values, xFor, yFor)} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />}
              {n > 0 && (
                <circle cx={xFor(n - 1)} cy={yFor(values[n - 1])} r={5} fill={s.color} stroke="var(--panel)" strokeWidth={2} />
              )}
            </g>
          );
        })}

        {hoverIndex !== null && (
          <line x1={xFor(hoverIndex)} x2={xFor(hoverIndex)} y1={PAD_T} y2={VIEW_H - PAD_B} className="trend-crosshair" />
        )}

        {/* Transparent full-height hit rect - the crosshair finds X, so the
            whole plot area is one hit target rather than per-point dots. */}
        <rect
          x={PAD_L}
          y={PAD_T}
          width={VIEW_W - PAD_L - PAD_R}
          height={VIEW_H - PAD_T - PAD_B}
          fill="transparent"
          onPointerMove={handlePointerMove}
          onPointerLeave={() => setHoverIndex(null)}
        />
      </svg>

      {hovered && (
        <div
          className="trend-tooltip"
          style={{
            left: tooltipOnRight ? `${(xFor(hoverIndex!) / VIEW_W) * 100}%` : undefined,
            right: tooltipOnRight ? undefined : `${100 - (xFor(hoverIndex!) / VIEW_W) * 100}%`,
          }}
        >
          <div className="trend-tooltip-date">{formatDateShort(hovered.date)}</div>
          {series.map((s) => (
            <div key={s.key} className="trend-tooltip-row">
              <span className="trend-legend-swatch" style={{ background: s.color }} />
              <span className="trend-tooltip-label">{s.label}</span>
              <span className="trend-tooltip-value">{(hovered[s.key] as number).toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Trends({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [days, setDays] = useState(90);
  const [trends, setTrends] = useState<TrendsResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [showTable, setShowTable] = useState(false);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);

  useEffect(() => {
    api.agents().then(setAgents);
  }, []);

  useEffect(() => {
    setLoading(true);
    api
      .trends(days, scannerFilterIds)
      .then(setTrends)
      .finally(() => setLoading(false));
  }, [days, scannerFilterIds]);

  const formatDateShort = useMemo(
    () => (date: string) => {
      const d = new Date(date + "T00:00:00Z");
      return d.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
    },
    []
  );

  const latestTotal = trends ? trends.series[trends.series.length - 1]?.totalHosts ?? null : null;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Trends</h2>

      <div className="list-controls">
        <div className="list-controls-filters">
          <label className="hide-empty-toggle">
            Scanner
            <ScannerMultiSelect agents={agents} selectedIds={scannerFilterIds} onChange={setScannerFilterIds} align="left" />
          </label>
        </div>
      </div>

      <div className="list-controls">
        <div className="filter-chips">
          {DAY_PRESETS.map((d) => (
            <button key={d} className={`chip ${days === d ? "active" : ""}`} onClick={() => setDays(d)}>
              Last {d} days
            </button>
          ))}
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

      {loading || !trends ? (
        <p>Loading...</p>
      ) : (
        <>
          <section>
            <h2>
              Total hosts (all time){" "}
              {latestTotal !== null && <span className="trend-hero">{latestTotal.toLocaleString()}</span>}
            </h2>
            {showTable ? (
              <TrendTable data={trends.series} columns={[{ key: "totalHosts", label: "Total hosts" }]} />
            ) : (
              <TrendChart
                data={trends.series}
                series={[{ key: "totalHosts", label: "Total hosts", color: "var(--chart-headline)" }]}
                formatDateShort={formatDateShort}
              />
            )}
          </section>

          <section>
            <h2>Daily activity</h2>
            {showTable ? (
              <TrendTable
                data={trends.series}
                columns={[
                  { key: "newHosts", label: "New hosts" },
                  { key: "scans", label: "Scans" },
                  { key: "openPorts", label: "Open ports seen" },
                  { key: "cveMatches", label: "CVE matches seen" },
                ]}
              />
            ) : (
              <TrendChart data={trends.series} series={ACTIVITY_SERIES} formatDateShort={formatDateShort} />
            )}
          </section>
        </>
      )}
    </div>
  );
}

function TrendTable({
  data,
  columns,
}: {
  data: TrendsResult["series"];
  columns: Array<{ key: SeriesKey; label: string }>;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            {columns.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {[...data].reverse().map((d) => (
            <tr key={d.date}>
              <td>{d.date}</td>
              {columns.map((c) => (
                <td key={c.key}>{(d[c.key] as number).toLocaleString()}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
