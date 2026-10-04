import type { ScannerAgent } from "../api";
import ScannerMultiSelect from "./ScannerMultiSelect";

// The scanner choice for a scan that can be split: pick one scanner as
// before, or several to divide the target between them so it finishes
// sooner (the webserver's lib/scanSplit.ts does the dividing). Shared by
// Ad-hoc Scans and Schedule Scans, so the two explain the trade-off the
// same way.
export default function ScannerSplitFields({
  agents,
  selectedIds,
  onChange,
  rateSplit,
  onRateSplitChange,
  masscanRate,
}: {
  agents: ScannerAgent[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  rateSplit: boolean;
  onRateSplitChange: (value: boolean) => void;
  masscanRate: string;
}) {
  const n = selectedIds.length;
  const rate = Number(masscanRate);
  const hasRate = masscanRate.trim() !== "" && Number.isFinite(rate) && rate > 0;
  return (
    <>
      <label>
        Scanner{n > 1 ? `s (${n})` : ""}
        <ScannerMultiSelect agents={agents} selectedIds={selectedIds} onChange={onChange} emptyLabel="Pick a scanner" />
      </label>
      {n > 1 && (
        <>
          <p className="empty scanner-split-note">
            The target is divided between the {n} scanners. Every address always goes to the same scanner, so a host
            keeps one record rather than moving between scanners from one scan to the next - which also means the
            shares are only roughly equal, especially for a small target. Pick only scanners that can actually reach
            this network. "Estimate time" shows each scanner's share.
          </p>
          <label className="hide-empty-toggle window-toggle">
            <input type="checkbox" checked={rateSplit} onChange={(e) => onRateSplitChange(e.target.checked)} />
            Divide the scan rate between the scanners
          </label>
          <p className={rateSplit && !hasRate ? "callout-warning scanner-split-note" : "empty scanner-split-note"}>
            {/* The two choices speed up different halves of a scan, and
                saying so is the point: dividing the rate keeps the load on
                the target network the same, which by definition means
                masscan's discovery takes as long as it did. */}
            {rateSplit
              ? hasRate
                ? `The scan rate below is the total: each scanner runs at ${Math.max(1, Math.floor(rate / n)).toLocaleString()} packets/second, so the target network sees the same load as one scanner. Discovery therefore takes about as long as on one scanner; what finishes sooner is everything after it - nmap, screenshots, nuclei - which runs on ${n} scanners at once.`
                : "Enter a total scan rate below to divide between the scanners."
              : `Each scanner runs at its full rate, so discovery finishes up to ${n} times sooner - and the target network sees up to ${n} times the packets per second of a single scanner.`}
          </p>
        </>
      )}
    </>
  );
}
