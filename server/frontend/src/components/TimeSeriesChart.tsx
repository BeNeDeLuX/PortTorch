import { useEffect, useRef, useState } from "react";

// A line chart over real time, for scanner host metrics. Unlike the Trends
// chart, x is a timestamp rather than an index: a scanner that was offline
// for a day leaves a day-wide gap, and the line breaks there instead of
// drawing a straight segment across a period nobody measured.
//
// Each series can carry a faint "peak" line beside its average, because an
// hour's average hides exactly the one-minute spike a capacity question is
// about. Scans are drawn as shaded bands so a reader can see which scan made
// the load.

// The viewBox is as wide as the chart's container, measured, rather than a
// fixed width scaled to fit: a scaled 900-unit chart is centred with empty
// margins on a wide card and shrinks its axis labels on a narrow one.
const DEFAULT_W = 900;
const VIEW_H = 220;
const PAD_L = 84;
const PAD_R = 16;
const PAD_T = 12;
const PAD_B = 28;

export interface TimeSeries {
  label: string;
  color: string;
  values: Array<number | null>;
  // Optional peak per point, drawn faint under the average.
  peaks?: Array<number | null>;
  dashed?: boolean;
}

export interface TimeBand {
  start: number;
  end: number;
  label: string;
}

function niceMax(max: number): number {
  if (max <= 0) return 1;
  const magnitude = Math.pow(10, Math.floor(Math.log10(max)));
  const normalized = max / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

export default function TimeSeriesChart({
  times,
  from,
  to,
  gapMs,
  series,
  bands = [],
  yMax,
  format,
  formatTime,
  ariaLabel,
}: {
  times: number[];
  from: number;
  to: number;
  // Points further apart than this are not joined.
  gapMs: number;
  series: TimeSeries[];
  bands?: TimeBand[];
  // A fixed top of the axis (100 for percentages); otherwise rounded up.
  yMax?: number;
  format: (v: number) => string;
  formatTime: (t: number) => string;
  ariaLabel: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const [viewW, setViewW] = useState(DEFAULT_W);
  useEffect(() => {
    const el = boxRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      const w = Math.floor(el.getBoundingClientRect().width);
      if (w > 0) setViewW(Math.max(280, w));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const span = Math.max(1, to - from);
  const xFor = (t: number) => PAD_L + ((t - from) / span) * (viewW - PAD_L - PAD_R);
  const dataMax = Math.max(
    0,
    ...series.flatMap((s) => [...s.values, ...(s.peaks ?? [])].filter((v): v is number => v !== null))
  );
  const top = yMax ?? niceMax(dataMax * 1.05);
  const yFor = (v: number) => VIEW_H - PAD_B - (Math.min(v, top) / top) * (VIEW_H - PAD_T - PAD_B);

  // One path per unbroken run of points.
  function pathFor(values: Array<number | null>): string {
    let d = "";
    let prevT: number | null = null;
    values.forEach((v, i) => {
      if (v === null) {
        prevT = null;
        return;
      }
      const t = times[i];
      const move = prevT === null || t - prevT > gapMs;
      d += `${move ? "M" : "L"} ${xFor(t).toFixed(1)} ${yFor(v).toFixed(1)} `;
      prevT = t;
    });
    return d;
  }

  function handleMove(e: React.PointerEvent<SVGRectElement>) {
    if (times.length === 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    // The overlay rect spans exactly the plot area, so its fraction is time.
    const t = from + ((e.clientX - rect.left) / rect.width) * span;
    let best = 0;
    for (let i = 1; i < times.length; i++) if (Math.abs(times[i] - t) < Math.abs(times[best] - t)) best = i;
    setHover(best);
  }

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => top * f);
  const hoverX = hover !== null ? xFor(times[hover]) : 0;
  const tooltipOnRight = hoverX < viewW * 0.7;
  const hoveredBands = hover !== null ? bands.filter((b) => b.start <= times[hover] && b.end >= times[hover]) : [];

  return (
    <div className="trend-chart">
      <div className="trend-legend">
        {series.map((s) => (
          <span key={s.label} className="trend-legend-item">
            <span className="trend-legend-swatch" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
        {bands.length > 0 && (
          <span className="trend-legend-item">
            <span className="trend-legend-swatch metrics-band-swatch" />
            scan running
          </span>
        )}
      </div>
      <div ref={boxRef}>
        <svg viewBox={`0 0 ${viewW} ${VIEW_H}`} width="100%" height={VIEW_H} role="img" aria-label={ariaLabel}>
          {bands.map((b, i) => {
            const x1 = xFor(Math.max(b.start, from));
            const x2 = xFor(Math.min(b.end, to));
            return x2 > x1 ? (
              <rect key={i} x={x1} y={PAD_T} width={Math.max(1, x2 - x1)} height={VIEW_H - PAD_T - PAD_B} className="metrics-band" />
            ) : null;
          })}
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD_L} x2={viewW - PAD_R} y1={yFor(t)} y2={yFor(t)} className="trend-gridline" />
              <text x={PAD_L - 8} y={yFor(t)} className="trend-axis-label" textAnchor="end" dominantBaseline="middle">
                {format(t)}
              </text>
            </g>
          ))}
          <line x1={PAD_L} x2={viewW - PAD_R} y1={VIEW_H - PAD_B} y2={VIEW_H - PAD_B} className="trend-axis" />
          <text x={PAD_L} y={VIEW_H - PAD_B + 18} className="trend-axis-label" textAnchor="start">
            {formatTime(from)}
          </text>
          <text x={viewW - PAD_R} y={VIEW_H - PAD_B + 18} className="trend-axis-label" textAnchor="end">
            {formatTime(to)}
          </text>

          {series.map((s) => (
            <g key={s.label}>
              {s.peaks && <path d={pathFor(s.peaks)} fill="none" stroke={s.color} strokeWidth={1} opacity={0.35} />}
              <path
                d={pathFor(s.values)}
                fill="none"
                stroke={s.color}
                strokeWidth={2}
                strokeDasharray={s.dashed ? "5 4" : undefined}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
            </g>
          ))}

          {hover !== null && <line x1={hoverX} x2={hoverX} y1={PAD_T} y2={VIEW_H - PAD_B} className="trend-crosshair" />}
          <rect
            x={PAD_L}
            y={PAD_T}
            width={viewW - PAD_L - PAD_R}
            height={VIEW_H - PAD_T - PAD_B}
            fill="transparent"
            onPointerMove={handleMove}
            onPointerLeave={() => setHover(null)}
          />
        </svg>
      </div>
      {hover !== null && (
        <div
          className="trend-tooltip"
          style={{
            left: tooltipOnRight ? `${(hoverX / viewW) * 100}%` : undefined,
            right: tooltipOnRight ? undefined : `${100 - (hoverX / viewW) * 100}%`,
          }}
        >
          <div className="trend-tooltip-date">{formatTime(times[hover])}</div>
          {series.map((s) => (
            <div key={s.label} className="trend-tooltip-row">
              <span className="trend-legend-swatch" style={{ background: s.color }} />
              <span className="trend-tooltip-label">{s.label}</span>
              <span className="trend-tooltip-value">
                {s.values[hover] === null ? "-" : format(s.values[hover] as number)}
                {s.peaks && s.peaks[hover] !== null && ` (peak ${format(s.peaks[hover] as number)})`}
              </span>
            </div>
          ))}
          {hoveredBands.map((b, i) => (
            <div key={i} className="trend-tooltip-row host-meta">
              scan: {b.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
