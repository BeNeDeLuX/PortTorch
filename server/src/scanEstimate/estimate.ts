import { parseTargetSpecRanges } from "../lib/ipRange";
import { parsePortSpec } from "../lib/portSpec";

// What a scan would actually cost, before starting it. The scanner's own
// `--dry-run` answers this on the host; this is the same answer for
// someone about to queue a scan from the dashboard, who is the person
// most likely to type a /16 without picturing what that means.
//
// Both counts reuse the parsers this codebase already has - ipRange.ts
// for the target grammar (written for Network Coverage) and portSpec.ts
// for the port grammar (written for the port.closed inference). Neither
// needed changing, which is also the point: a third parser for the same
// two grammars is how the three would start disagreeing.
export interface ScanEstimate {
  // null means "not countable" - a hostname, which only the scanner's own
  // DNS resolves at scan time. Guessing 1 would be a claim, not a count.
  addresses: number | null;
  ports: number | null;
  probes: number | null;
  // Packets per second the estimate assumed, and where that number came
  // from, so an operator can tell a real reported rate from the fallback.
  rate: number;
  rateSource: "override" | "scanner" | "default";
  // masscan's own pass only. Everything after it (nmap, screenshots,
  // nuclei) depends entirely on how much is found, so estimating that
  // would be a guess dressed up as a number.
  masscanSeconds: number | null;
}

// masscan's own default, and what config.example.yaml ships. Only used
// when the chosen scanner has never reported its config.
export const DEFAULT_MASSCAN_RATE = 1000;

export function countAddresses(targetSpec: string): number | null {
  const trimmed = targetSpec.trim();
  if (!trimmed) return null;
  // An IPv6 target is an explicit address list by design (see the
  // scanner's parseIPv6TargetList), so it is countable - just not by the
  // IPv4 range parser.
  if (trimmed.includes(":")) {
    const parts = trimmed.split(",").map((p) => p.trim()).filter(Boolean);
    return parts.length > 0 ? parts.length : null;
  }
  const ranges = parseTargetSpecRanges(trimmed);
  if (!ranges) return null;
  return ranges.reduce((total, r) => total + (r.end - r.start + 1), 0);
}

export function countPorts(portSpec: string): number | null {
  const spec = parsePortSpec(portSpec);
  if (!spec) return null;
  // Ranges are stored rather than expanded by parsePortSpec, so this
  // counts them rather than enumerating - "1-65535" must not build a
  // 65k-entry set just to be counted.
  let total = spec.singles.size;
  for (const range of spec.ranges) {
    total += range.hi - range.lo + 1;
  }
  return total > 0 ? total : null;
}

export function estimateScan(
  targetSpec: string,
  portSpec: string,
  rate: number,
  rateSource: ScanEstimate["rateSource"]
): ScanEstimate {
  const addresses = countAddresses(targetSpec);
  const ports = countPorts(portSpec);
  const probes = addresses !== null && ports !== null ? addresses * ports : null;
  return {
    addresses,
    ports,
    probes,
    rate,
    rateSource,
    masscanSeconds: probes !== null && rate > 0 ? probes / rate : null,
  };
}

// Everything after discovery, projected from this scanner's own past
// scans rather than guessed. Each completed scan says how many addresses
// it covered, how many hosts it confirmed and how long it took; taking its
// estimated discovery pass off the duration leaves what enrichment (nmap,
// screenshots, nuclei, submission) cost per confirmed host. Two pooled
// ratios come out of that - hosts found per address, seconds per host -
// and the projection is addresses x hit rate x seconds per host.
//
// Honest rather than precise: a /24 of servers and a /24 of printers hit
// at very different rates, and a scan with nuclei on costs more per host
// than one without. So it is reported with how many scans it rests on,
// and not at all below MIN_HISTORY_SCANS.
export const MIN_HISTORY_SCANS = 3;

export interface PastScan {
  targetSpec: string;
  portSpec: string;
  durationSeconds: number;
  hostsScanned: number;
}

export interface EnrichmentProjection {
  basedOnScans: number;
  hitRate: number;
  secondsPerHost: number;
  expectedHosts: number;
  enrichmentSeconds: number;
}

export function projectEnrichment(history: PastScan[], addresses: number, rate: number): EnrichmentProjection | null {
  let scans = 0;
  let totalAddresses = 0;
  let totalHosts = 0;
  let enrichSeconds = 0;
  for (const h of history) {
    const est = estimateScan(h.targetSpec, h.portSpec, rate, "scanner");
    if (est.addresses === null || est.masscanSeconds === null || est.addresses === 0) continue;
    scans++;
    totalAddresses += est.addresses;
    totalHosts += h.hostsScanned;
    enrichSeconds += Math.max(0, h.durationSeconds - est.masscanSeconds);
  }
  if (scans < MIN_HISTORY_SCANS || totalAddresses === 0 || totalHosts === 0) return null;
  const hitRate = totalHosts / totalAddresses;
  const secondsPerHost = enrichSeconds / totalHosts;
  const expectedHosts = addresses * hitRate;
  return { basedOnScans: scans, hitRate, secondsPerHost, expectedHosts, enrichmentSeconds: expectedHosts * secondsPerHost };
}
