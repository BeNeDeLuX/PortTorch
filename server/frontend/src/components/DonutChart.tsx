import { useId, useState } from "react";

export interface DonutSlice {
  label: string;
  value: number;
}

const SIZE = 200;
const R_OUTER = 92;
const R_INNER = 58;
const CX = SIZE / 2;
const CY = SIZE / 2;

// Eight categorical slots (styles.css) - slots 1-5 are the same colors
// the Trends line chart already uses, so a hue means the same kind of
// thing across the whole app, and slot 8 is deliberately the muted token
// because it is where "Other" lands.
const SLICE_COLORS = [
  "var(--chart-cat-1)",
  "var(--chart-cat-2)",
  "var(--chart-cat-3)",
  "var(--chart-cat-4)",
  "var(--chart-cat-5)",
  "var(--chart-cat-6)",
  "var(--chart-cat-7)",
  "var(--chart-cat-8)",
];

function sliceColor(index: number, label: string, overrides?: Record<string, string>): string {
  // A chart whose slices have a real severity order (certificate expiry:
  // expired, then soon, then fine) passes an explicit mapping instead -
  // rendering "Expired" in whatever categorical color slot 1 happens to
  // be says nothing, while --danger says exactly the right thing.
  if (overrides?.[label]) return overrides[label];
  // "Other" is a residual, not a category, and always gets the muted
  // slot regardless of where it happens to land in the order.
  if (label === "Other" || label === "unknown" || label === "Unknown") return "var(--chart-cat-8)";
  return SLICE_COLORS[index % SLICE_COLORS.length];
}

function polar(angle: number, radius: number): [number, number] {
  // -90deg so the first slice starts at 12 o'clock rather than 3 o'clock.
  const rad = ((angle - 90) * Math.PI) / 180;
  return [CX + radius * Math.cos(rad), CY + radius * Math.sin(rad)];
}

function arcPath(startAngle: number, endAngle: number): string {
  const [x1, y1] = polar(startAngle, R_OUTER);
  const [x2, y2] = polar(endAngle, R_OUTER);
  const [x3, y3] = polar(endAngle, R_INNER);
  const [x4, y4] = polar(startAngle, R_INNER);
  const large = endAngle - startAngle > 180 ? 1 : 0;
  return [
    `M ${x1.toFixed(2)} ${y1.toFixed(2)}`,
    `A ${R_OUTER} ${R_OUTER} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`,
    `L ${x3.toFixed(2)} ${y3.toFixed(2)}`,
    `A ${R_INNER} ${R_INNER} 0 ${large} 0 ${x4.toFixed(2)} ${y4.toFixed(2)}`,
    "Z",
  ].join(" ");
}

// Donut chart, plain inline SVG like the Trends line chart - no chart
// library, same reasoning (see the .trend-chart CSS block).
//
// Every slice's identity comes from its legend row below the donut,
// which always carries the label and the number - never from color
// alone, so
// the two light-mode slots that fall under the 3:1 contrast target (the
// same two the Trends palette already documents) stay readable, and the
// page's Chart/Table toggle is the full relief valve on top of that.
export default function DonutChart({
  slices,
  unit,
  colors,
}: {
  slices: DonutSlice[];
  unit?: string;
  colors?: Record<string, string>;
}) {
  const [hovered, setHovered] = useState<number | null>(null);
  const titleId = useId();

  const total = slices.reduce((sum, s) => sum + s.value, 0);
  if (total === 0) {
    return <p className="empty">Nothing scanned yet for this filter.</p>;
  }

  const share = (value: number) => (value / total) * 100;
  const formatShare = (value: number) => {
    const pct = share(value);
    // A slice worth less than 0.1% still exists - reporting it as "0.0%"
    // reads as "none", so it gets a "<0.1%" instead.
    return pct > 0 && pct < 0.1 ? "<0.1%" : `${pct.toFixed(1)}%`;
  };

  let angle = 0;
  const arcs = slices.map((s, i) => {
    const start = angle;
    const end = angle + (s.value / total) * 360;
    angle = end;
    return { slice: s, index: i, start, end, color: sliceColor(i, s.label, colors) };
  });

  const active = hovered !== null ? arcs[hovered] : null;

  return (
    <div className="donut-chart">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} width={SIZE} height={SIZE} role="img" aria-labelledby={titleId}>
        <title id={titleId}>
          {slices.map((s) => `${s.label}: ${s.value.toLocaleString()} (${formatShare(s.value)})`).join(", ")}
        </title>
        {arcs.map((a) => (
          <path
            key={a.slice.label}
            // A single slice covering the whole circle can't be drawn as
            // an arc (start and end point are identical, so the A command
            // renders nothing) - two half-circles cover that case.
            d={
              a.end - a.start >= 359.999
                ? `${arcPath(0, 180)} ${arcPath(180, 360)}`
                : arcPath(a.start, a.end)
            }
            fill={a.color}
            className={`donut-slice${hovered !== null && hovered !== a.index ? " dimmed" : ""}`}
            onPointerEnter={() => setHovered(a.index)}
            onPointerLeave={() => setHovered(null)}
          />
        ))}
        <text x={CX} y={CY - 6} className="donut-center-value" textAnchor="middle">
          {(active ? active.slice.value : total).toLocaleString()}
        </text>
        <text x={CX} y={CY + 12} className="donut-center-label" textAnchor="middle">
          {active ? formatShare(active.slice.value) : unit ?? "total"}
        </text>
      </svg>

      <ul className="donut-legend">
        {arcs.map((a) => (
          <li
            key={a.slice.label}
            className={hovered !== null && hovered !== a.index ? "dimmed" : ""}
            onPointerEnter={() => setHovered(a.index)}
            onPointerLeave={() => setHovered(null)}
          >
            <span className="donut-legend-swatch" style={{ background: a.color }} />
            <span className="donut-legend-label">{a.slice.label}</span>
            <span className="donut-legend-value">{a.slice.value.toLocaleString()}</span>
            <span className="donut-legend-share">{formatShare(a.slice.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
