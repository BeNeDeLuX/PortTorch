import { useState } from "react";
import { api, ScanEstimate as Estimate } from "../api";
import { IconInfo } from "./icons";

// Answers "how long will this take?" before the scan is queued - the same
// question the scanner's own `porttorch scan --dry-run` answers on the
// host, for the person who never touches the host. A /16 across every
// port and a /24 across ten look equally reasonable typed into a form;
// they are four seconds and seven weeks apart.
//
// On demand rather than live as you type: it is a real request, and a
// half-typed target spec produces a number that changes under you, which
// is worse than no number.
export default function ScanEstimateButton({
  targetSpec,
  portSpec,
  scannerAgentId,
  masscanRate,
}: {
  targetSpec: string;
  portSpec: string;
  scannerAgentId?: string;
  masscanRate?: string;
}) {
  const [estimate, setEstimate] = useState<Estimate | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = targetSpec.trim() !== "" && portSpec.trim() !== "";

  async function handleEstimate() {
    setBusy(true);
    setError(null);
    setEstimate(null);
    try {
      const rate = masscanRate?.trim() ? Number(masscanRate) : undefined;
      setEstimate(
        await api.estimateScan({
          targetSpec: targetSpec.trim(),
          portSpec: portSpec.trim(),
          ...(scannerAgentId ? { scannerAgentId } : {}),
          ...(rate && Number.isFinite(rate) && rate > 0 ? { masscanRate: rate } : {}),
        })
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not estimate this scan.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button type="button" className="btn-icon-label" onClick={handleEstimate} disabled={!ready || busy}>
        <IconInfo /> {busy ? "Calculating..." : "Estimate time"}
      </button>
      {error && <p className="error">{error}</p>}
      {estimate && <EstimateResult estimate={estimate} />}
    </>
  );
}

function EstimateResult({ estimate }: { estimate: Estimate }) {
  // A target this cannot count is a hostname, which is a perfectly valid
  // thing to scan - so it says which half is unknown and why, rather than
  // failing or showing a zero.
  if (estimate.addresses === null || estimate.probes === null) {
    return (
      <div className="callout">
        <p>
          {estimate.addresses === null
            ? "This target is a hostname, so only the scanner's own DNS can say how many addresses it covers - the estimate needs that number."
            : "This port spec could not be read, so there is nothing to count."}
          {estimate.ports !== null && ` The port spec covers ${estimate.ports.toLocaleString()} port(s) per address.`}
        </p>
      </div>
    );
  }

  return (
    <div className="callout">
      <dl className="settings-facts">
        <dt>Addresses</dt>
        <dd>{estimate.addresses.toLocaleString()}</dd>
        <dt>Ports</dt>
        <dd>{estimate.ports?.toLocaleString()} per address</dd>
        <dt>Probes</dt>
        <dd>{estimate.probes.toLocaleString()}</dd>
        <dt>Rate</dt>
        <dd>
          {estimate.rate.toLocaleString()} packets/second{" "}
          <span className="empty">
            {estimate.rateSource === "override"
              ? "(the rate you entered)"
              : estimate.rateSource === "scanner"
                ? "(this scanner's own configured rate)"
                : "(masscan's default - this scanner hasn't reported its config)"}
          </span>
        </dd>
        <dt>Discovery</dt>
        <dd>
          <strong>{formatDuration(estimate.masscanSeconds ?? 0)}</strong>
        </dd>
      </dl>
      <p className="empty">
        That is masscan's discovery pass only. What follows it - nmap service detection, screenshots, nuclei - depends
        entirely on how many open ports are actually found, so it cannot be estimated up front. A scan that finds a lot
        will take meaningfully longer than this.
      </p>
    </div>
  );
}

// Minutes and hours are what this is read in; seconds below a minute and
// a bare second count above an hour are both noise.
function formatDuration(seconds: number): string {
  if (seconds < 90) return `about ${Math.round(seconds)} seconds`;
  if (seconds < 5400) return `about ${Math.round(seconds / 60)} minutes`;
  if (seconds < 172800) return `about ${(seconds / 3600).toFixed(1)} hours`;
  return `about ${(seconds / 86400).toFixed(1)} days`;
}
