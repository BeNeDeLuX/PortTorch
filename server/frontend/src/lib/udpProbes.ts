// Which of the scanner's four fixed UDP probes a port spec triggers.
//
// The scanner runs DNS recursion (53), SNMP (161), IPMI (623) and UPnP
// (1900) as separate probes, and since scanner 0.30.2 only when the port
// is in the requested spec (scanner/internal/pipeline/udpprobes.go's
// fixedUDPProbeInScope). Before that they ran on every scan, so a narrow
// schedule like "22,80,443" silently stopped collecting SNMP and IPMI data
// with that release. This mirrors the Go rule so a form and the schedule
// list can say which probes a spec includes - a separate copy, as with the
// other scanner-side rules this frontend mirrors:
//
//   - a bare part counts ("1-10000" covers 161);
//   - a "U:" part counts;
//   - a "T:" part does not, being explicitly TCP only.

export interface UdpProbe {
  port: number;
  label: string;
}

export const FIXED_UDP_PROBES: UdpProbe[] = [
  { port: 53, label: "DNS recursion" },
  { port: 161, label: "SNMP" },
  { port: 623, label: "IPMI" },
  { port: 1900, label: "UPnP" },
];

export function udpProbeInScope(portSpec: string, port: number): boolean {
  for (let part of portSpec.split(",")) {
    part = part.trim();
    if (part === "") continue;
    if (part.length > 2 && part[1] === ":") {
      if (part[0] === "T" || part[0] === "t") continue;
      part = part.slice(2);
    }
    const [lo, hi = lo] = part.split("-");
    const l = Number(lo.trim());
    const h = Number(hi.trim());
    if (Number.isInteger(l) && Number.isInteger(h) && lo.trim() !== "" && l <= port && port <= h) return true;
  }
  return false;
}

export function udpProbesInScope(portSpec: string): UdpProbe[] {
  return FIXED_UDP_PROBES.filter((p) => udpProbeInScope(portSpec, p.port));
}
