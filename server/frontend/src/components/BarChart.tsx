export interface BarItem {
  label: string;
  value: number;
}

// Horizontal bars for a small, named set - the per-scanner breakdown on
// the Scan Stats page. Horizontal rather than vertical specifically
// because the labels are scanner names, which are arbitrary length and
// would need rotating on a column chart.
//
// Bars are scaled to the largest value in this chart alone, not shared
// across the three charts beside it: each answers "how do the scanners
// compare on this metric", and a shared scale would flatten the
// certificate chart to invisibility next to the port counts.
export default function BarChart({ items, color }: { items: BarItem[]; color: string }) {
  if (items.length === 0) {
    return <p className="empty">No scanners have reported data yet.</p>;
  }
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="bar-chart">
      {items.map((item) => (
        <li key={item.label}>
          <span className="bar-chart-label" title={item.label}>
            {item.label}
          </span>
          <span className="bar-chart-track">
            <span
              className="bar-chart-fill"
              style={{ width: `${(item.value / max) * 100}%`, background: color }}
            />
          </span>
          <span className="bar-chart-value">{item.value.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}
