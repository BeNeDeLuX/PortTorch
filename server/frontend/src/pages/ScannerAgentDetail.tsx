import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { api, Me, ScannerMetrics, ScannerMetricsRange } from "../api";
import PageHeader from "../components/PageHeader";
import TimeSeriesChart, { TimeBand } from "../components/TimeSeriesChart";
import { formatDateTime } from "../lib/formatDate";

// Per-scanner host metrics: CPU, memory, network throughput and running
// scans over a chosen range, so "is this scanner keeping up, and what made
// it busy" is answerable without a shell on the host. The scanner samples
// /proc once a minute in serve mode; long ranges read the hourly roll-up.

const RANGES: Array<{ value: ScannerMetricsRange; label: string }> = [
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "14d", label: "14 days" },
  { value: "30d", label: "30 days" },
  { value: "90d", label: "90 days" },
  { value: "365d", label: "1 year" },
];

const RANGE_KEY = "porttorch.scannerMetrics.range";

function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

// Network throughput reads in bits per second, the unit links are sold and
// monitored in - "40 Mbit/s" is comparable to a 1 Gbit uplink at a glance.
function formatBitRate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let v = bits;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function storedRange(): ScannerMetricsRange {
  try {
    const v = localStorage.getItem(RANGE_KEY);
    if (v && RANGES.some((r) => r.value === v)) return v as ScannerMetricsRange;
  } catch {
    // Storage unavailable - fall through to the default.
  }
  return "24h";
}

export default function ScannerAgentDetail({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const { id } = useParams<{ id: string }>();
  const [range, setRange] = useState<ScannerMetricsRange>(storedRange);
  const [data, setData] = useState<ScannerMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    const load = () => {
      api
        .scannerMetrics(id, range)
        .then((d) => {
          if (cancelled) return;
          setData(d);
          setError(null);
        })
        .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Failed to load metrics"))
        .finally(() => !cancelled && setLoading(false));
    };
    setLoading(true);
    load();
    // A minute is the sampling interval; refreshing faster would only
    // fetch the same points again.
    const timer = window.setInterval(load, 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [id, range]);

  function pickRange(r: ScannerMetricsRange) {
    setRange(r);
    try {
      localStorage.setItem(RANGE_KEY, r);
    } catch {
      // Remembering the range is a convenience only.
    }
  }

  const view = useMemo(() => {
    if (!data) return null;
    const times = data.points.map((p) => Date.parse(p.t));
    const from = Date.parse(data.from);
    const to = Date.parse(data.to);
    // Points further apart than a few buckets are a gap (scanner offline or
    // not yet reporting), not a straight line across it.
    const gapMs = Math.max(data.bucketSeconds * 1000 * 2.5, 3 * 60_000);
    const bands: TimeBand[] = data.scans.map((s) => ({
      start: Date.parse(s.startedAt),
      end: s.finishedAt ? Date.parse(s.finishedAt) : to,
      label: `${s.targetSpec} (${s.status})`,
    }));
    const memTotal = data.points.reduce((m, p) => Math.max(m, p.memTotal), 0);
    return { times, from, to, gapMs, bands, memTotal };
  }, [data]);

  const fmtTime = (t: number) => formatDateTime(new Date(t), me.preferences);
  const latest = data?.latest ?? null;
  const memPercent = latest && latest.memTotalBytes > 0 ? (100 * latest.memUsedBytes) / latest.memTotalBytes : null;

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <p>
        <Link to="/agents">← Scanner Agents</Link>
      </p>
      <h2>{data ? data.agent.name : "Scanner"}</h2>
      {data && (
        <p className="host-meta">
          Version {data.agent.version ?? "unknown"} ·{" "}
          {data.source === "minute"
            ? "one sample per minute"
            : "hourly averages, with the hourly peak drawn faint behind each line"}
          {data.bucketSeconds > 60 && ` · each point covers ${Math.round(data.bucketSeconds / 60)} min`}
        </p>
      )}

      <div className="list-controls">
        <div className="filter-chips">
          {RANGES.map((r) => (
            <button key={r.value} className={`chip ${range === r.value ? "active" : ""}`} onClick={() => pickRange(r.value)}>
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {loading && !data && <p className="empty">Loading...</p>}

      {latest && (
        <div className="stat-tiles">
          <div className="stat-tile">
            <div className="stat-tile-value">{latest.cpuPercent.toFixed(0)}%</div>
            <div className="stat-tile-label">CPU · load {latest.load1.toFixed(2)}</div>
          </div>
          <div className="stat-tile">
            <div className="stat-tile-value">{memPercent === null ? "-" : `${memPercent.toFixed(0)}%`}</div>
            <div className="stat-tile-label">
              Memory · {formatBytes(latest.memUsedBytes)} of {formatBytes(latest.memTotalBytes)}
            </div>
          </div>
          <div className="stat-tile">
            <div className="stat-tile-value">{formatBitRate(latest.netRxBytesPerSec)}</div>
            <div className="stat-tile-label">Network in</div>
          </div>
          <div className="stat-tile">
            <div className="stat-tile-value">{formatBitRate(latest.netTxBytesPerSec)}</div>
            <div className="stat-tile-label">Network out</div>
          </div>
          <div className="stat-tile">
            <div className="stat-tile-value">{latest.scansRunning}</div>
            <div className="stat-tile-label">Scans running · as of {fmtTime(Date.parse(latest.at))}</div>
          </div>
        </div>
      )}

      {data && view && data.points.length === 0 && (
        <p className="empty">
          No measurements in this range. A scanner reports them once a minute while it runs in serve mode, from
          version 0.30.0 on - an older scanner, or one started with "scan" or "menu", sends none.
        </p>
      )}

      {data && view && data.points.length > 0 && (
        <>
          <h3>CPU</h3>
          <TimeSeriesChart
            times={view.times}
            from={view.from}
            to={view.to}
            gapMs={view.gapMs}
            bands={view.bands}
            yMax={100}
            format={(v) => `${v.toFixed(0)}%`}
            formatTime={fmtTime}
            ariaLabel="CPU usage over time"
            series={[
              {
                label: "CPU",
                color: "var(--chart-series-1)",
                values: data.points.map((p) => p.cpu),
                peaks: data.source === "hourly" ? data.points.map((p) => p.cpuMax) : undefined,
              },
            ]}
          />

          <h3>Memory{view.memTotal > 0 && <span className="host-meta"> · top of the chart is the installed {formatBytes(view.memTotal)}</span>}</h3>
          <TimeSeriesChart
            times={view.times}
            from={view.from}
            to={view.to}
            gapMs={view.gapMs}
            bands={view.bands}
            yMax={view.memTotal > 0 ? view.memTotal : undefined}
            format={formatBytes}
            formatTime={fmtTime}
            ariaLabel="Memory usage over time"
            series={[
              {
                label: "Used",
                color: "var(--chart-series-2)",
                values: data.points.map((p) => p.memUsed),
                peaks: data.source === "hourly" ? data.points.map((p) => p.memMax) : undefined,
              },
            ]}
          />

          <h3>Network</h3>
          <TimeSeriesChart
            times={view.times}
            from={view.from}
            to={view.to}
            gapMs={view.gapMs}
            bands={view.bands}
            format={formatBitRate}
            formatTime={fmtTime}
            ariaLabel="Network throughput over time"
            series={[
              {
                label: "In",
                color: "var(--chart-series-1)",
                values: data.points.map((p) => p.rx),
                peaks: data.source === "hourly" ? data.points.map((p) => p.rxMax) : undefined,
              },
              {
                label: "Out",
                color: "var(--chart-series-3)",
                values: data.points.map((p) => p.tx),
                peaks: data.source === "hourly" ? data.points.map((p) => p.txMax) : undefined,
              },
            ]}
          />

          <h3>Scans running</h3>
          <TimeSeriesChart
            times={view.times}
            from={view.from}
            to={view.to}
            gapMs={view.gapMs}
            format={(v) => (Number.isInteger(v) ? String(v) : v.toFixed(1))}
            formatTime={fmtTime}
            ariaLabel="Scans running over time"
            series={[{ label: "Scans", color: "var(--chart-series-4)", values: data.points.map((p) => p.scans) }]}
          />
        </>
      )}
    </div>
  );
}
