// Which of the scanner's four fixed UDP probes a port spec triggers - the
// webserver's copy of scanner/internal/pipeline/udpprobes.go's
// fixedUDPProbeInScope (same separate-copy convention as lib/portSpec.ts),
// used by the scan estimate to say what a scan will actually send.
//
// A bare or "U:" part covering the port counts; a "T:" part does not.

export const FIXED_UDP_PROBES = [
  { port: 53, label: "DNS recursion" },
  { port: 161, label: "SNMP" },
  { port: 623, label: "IPMI" },
  { port: 1900, label: "UPnP" },
] as const;

export function udpProbeInScope(portSpec: string, port: number): boolean {
  for (let part of portSpec.split(",")) {
    part = part.trim();
    if (part === "") continue;
    if (part.length > 2 && part[1] === ":") {
      if (part[0] === "T" || part[0] === "t") continue;
      part = part.slice(2);
    }
    const [lo, hi = lo] = part.split("-");
    if (lo.trim() === "") continue;
    const l = Number(lo.trim());
    const h = Number(hi.trim());
    if (Number.isInteger(l) && Number.isInteger(h) && l <= port && port <= h) return true;
  }
  return false;
}

export function udpProbesInScope(portSpec: string): Array<{ port: number; label: string }> {
  return FIXED_UDP_PROBES.filter((p) => udpProbeInScope(portSpec, p.port)).map((p) => ({ ...p }));
}
