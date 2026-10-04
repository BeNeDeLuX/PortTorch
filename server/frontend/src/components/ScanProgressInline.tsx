import type { ScanProgressCounts } from "../api";
import { progressView } from "../lib/scanProgress";

// A running scan's progress in one line, for the lists of running scans
// (the Dashboard banner, Scanner Agents) - so how far along each one is
// shows without opening its Details. Same numbers and the same rules as
// the popup's bars (lib/scanProgress.ts): nothing until discovery has
// reported, floored so 100% only ever means done, and a host total marked
// provisional while discovery blocks remain.
export default function ScanProgressInline({ counts }: { counts: ScanProgressCounts | null }) {
  const view = progressView(counts);
  if (view.nothingFound) return <span className="host-meta">no hosts found</span>;
  if (!view.hosts && view.discovery) {
    return (
      <span className="scan-progress-inline" title="A large target is discovered in blocks">
        <span className="scan-progress-inline-bar" aria-hidden="true">
          <span style={{ width: `${view.discovery.percent}%` }} />
        </span>
        <span className="host-meta">
          discovery {view.discovery.done}/{view.discovery.total}
        </span>
      </span>
    );
  }
  if (!view.hosts) return null;
  const { percent, processed, discovered, final } = view.hosts;
  const label = `${percent}% · ${processed}/${discovered} hosts${final ? "" : " so far"}`;
  return (
    <span
      className="scan-progress-inline"
      role="progressbar"
      aria-label="Hosts processed"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
      title={view.discovery ? `Discovery block ${view.discovery.done} of ${view.discovery.total} - more hosts may follow` : undefined}
    >
      <span className="scan-progress-inline-bar" aria-hidden="true">
        <span style={{ width: `${percent}%` }} />
      </span>
      <span className="host-meta">{label}</span>
    </span>
  );
}
