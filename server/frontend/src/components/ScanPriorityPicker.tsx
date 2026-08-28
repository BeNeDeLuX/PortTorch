import { ScanPriority } from "../api";

// The one control for picking where a scan request lands in its scanner's
// claim order, shared by the Rescan popup, the Ad-hoc Scans form and the
// Schedules form - same "one shared control so the three can't drift"
// reasoning as ScanProfilePicker/NucleiProfilePicker, and the same shape:
// a bare <select> (plus a hint), with the surrounding <label> left to the
// caller so it slots into each form's own layout.
//
// The hint spells out that this reorders rather than parallelizes,
// because a scanner runs exactly one scan at a time and its polling loop
// blocks for that scan's whole duration - so what High actually buys is
// "next in line once the current scan ends", not "starts now".
export default function ScanPriorityPicker({
  value,
  onChange,
  disabled,
}: {
  value: ScanPriority;
  onChange: (next: ScanPriority) => void;
  disabled?: boolean;
}) {
  return (
    <>
      <select
        className="scan-priority-select"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value as ScanPriority)}
      >
        <option value="high">High - ahead of Normal and Low</option>
        <option value="normal">Normal</option>
        <option value="low">Low - behind everything else</option>
      </select>
      <p className="empty">
        A scanner runs one scan at a time and picks the highest-priority request waiting for it once the current one
        finishes - this reorders the queue, it doesn't run more at once. Same-priority requests stay first-in-first-out.
      </p>
    </>
  );
}
