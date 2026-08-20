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
export default function ScanRateSupportNote({
  agent,
  rate,
}: {
  agent: ScannerAgent | undefined;
  rate: string;
}) {
  if (!rate.trim()) return null;

  const support = capabilitySupport(agent, "scanRate");
  if (support === "supported") return null;

  if (support === "too-old") {
    return (
      <p className="callout-danger">
        <strong>{agent?.name}</strong> reports scanner v{agent?.version}, which ignores the scan rate - it needs
        v{MIN_SCANNER_VERSION.scanRate} or newer. The scan would run at that scanner's own configured rate instead,
        without any error. Update it from Scanning → Scanner Agents, or leave the rate blank.
      </p>
    );
  }

  return (
    <p className="empty">
      This scanner hasn't reported its version yet (it has never polled), so whether it honors the scan rate can't be
      confirmed - it needs v{MIN_SCANNER_VERSION.scanRate} or newer. An older one would silently use its own
      configured rate.
    </p>
  );
}
