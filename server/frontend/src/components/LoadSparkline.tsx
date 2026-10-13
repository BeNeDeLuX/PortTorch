import { Link } from "react-router";
import { ScannerMetricsSummary } from "../api";
import { formatBitRate } from "../lib/units";

// A scanner's last 24 hours at a glance, for the Scanner Agents list: CPU
// as a line (0-100%, fixed scale so two scanners' lines compare) and the
// current CPU, network and disk beside it. Links to the full charts.
const W = 120;
const H = 26;

export default function LoadSparkline({ agentId, summary }: { agentId: string; summary: ScannerMetricsSummary | undefined }) {
  if (!summary || (summary.spark.length === 0 && !summary.latest)) {
    return <span className="host-meta" title="This scanner reports no host metrics (scanner 0.30.0+ in serve mode)">-</span>;
  }
  const points = summary.spark;
  const t0 = points.length > 0 ? Date.parse(points[0].t) : 0;
  const t1 = points.length > 0 ? Date.parse(points[points.length - 1].t) : 1;
  const x = (t: string) => (points.length < 2 ? W / 2 : ((Date.parse(t) - t0) / Math.max(1, t1 - t0)) * (W - 2) + 1);
  const y = (cpu: number) => H - 1 - (Math.min(100, cpu) / 100) * (H - 2);
  const d = points.map((p, i) => `${i === 0 ? "M" : "L"} ${x(p.t).toFixed(1)} ${y(p.cpu).toFixed(1)}`).join(" ");
  const latest = summary.latest;
  return (
    <Link to={`/agents/${agentId}`} className="load-sparkline" title="CPU over the last 24 hours - open for CPU, memory, network and disk charts">
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} aria-hidden="true">
        <line x1={0} x2={W} y1={H - 1} y2={H - 1} className="trend-axis" />
        <path d={d} fill="none" stroke="var(--chart-series-1)" strokeWidth={1.5} />
      </svg>
      {latest && (
        <span className={`host-meta${summary.pressure || summary.diskLow ? " load-sparkline-alert" : ""}`}>
          CPU {latest.cpuPercent.toFixed(0)}% · {formatBitRate(latest.netBytesPerSec)}
          {latest.diskFreePercent !== null && ` · disk ${latest.diskFreePercent.toFixed(0)}% free`}
        </span>
      )}
    </Link>
  );
}
