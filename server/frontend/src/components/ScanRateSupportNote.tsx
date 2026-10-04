import { ScannerAgent } from "../api";
import { MIN_SCANNER_VERSION, capabilitySupport } from "../lib/scannerCapabilities";

// Shown under the scan-rate field on Ad-hoc Scans and Schedule Scans when
// a rate is actually entered - silent otherwise, since the vast majority
// of scans don't set one and a permanent version caveat would just be
// noise.
//
// Deliberately a warning rather than a hard block: the setting is still
// stored on the request, so it takes effect the moment that scanner is
// updated (the Scanner Agents page can trigger that in place), and
// blocking would be wrong for a schedule created ahead of a planned
// rollout.
//
// Takes every scanner the scan will run on and says each thing once,
// naming the scanners it applies to - a split scan across three scanners
// that have never polled used to print the same unnamed paragraph three
// times.
export default function ScanRateSupportNote({
  agents,
  rate,
}: {
  agents: (ScannerAgent | undefined)[];
  rate: string;
}) {
  if (!rate.trim()) return null;

  const known = agents.filter((a): a is ScannerAgent => a !== undefined);
  const tooOld = known.filter((a) => capabilitySupport(a, "scanRate") === "too-old");
  const unknown = known.filter((a) => capabilitySupport(a, "scanRate") === "unknown");
  if (tooOld.length === 0 && unknown.length === 0) return null;
  const single = known.length === 1;

  return (
    <>
      {tooOld.length > 0 && (
        <p className="callout-danger">
          {tooOld.map((a, i) => (
            <span key={a.id}>
              {i > 0 && ", "}
              <strong>{a.name}</strong> (v{a.version})
            </span>
          ))}{" "}
          {tooOld.length === 1 ? "ignores" : "ignore"} the scan rate - it needs v{MIN_SCANNER_VERSION.scanRate} or
          newer. The scan would run at {tooOld.length === 1 ? "that scanner's" : "those scanners'"} own configured
          rate instead, without any error. Update from Scanning → Scanner Agents, or leave the rate blank.
        </p>
      )}
      {unknown.length > 0 && (
        <p className="empty">
          {single ? "This scanner hasn't" : `${unknown.map((a) => a.name).join(", ")} ${unknown.length === 1 ? "hasn't" : "haven't"}`}{" "}
          reported {single || unknown.length === 1 ? "its version" : "their versions"} yet (never polled), so whether{" "}
          {single || unknown.length === 1 ? "it honors" : "they honor"} the scan rate can't be confirmed - it needs v
          {MIN_SCANNER_VERSION.scanRate} or newer. An older one would silently use its own configured rate.
        </p>
      )}
    </>
  );
}
