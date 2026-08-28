// Parsing a scan's requested port spec ("80,443,8000-8010,U:53") server-side.
//
// The Go scanner has its own equivalent (pipeline/excludes.go's
// parseProtoPortSet, used to subtract port excludes before masscan runs);
// this is a deliberate second implementation rather than something
// shared, same reasoning as the three independent compareSemver copies -
// crossing the language boundary isn't worth the coupling for a grammar
// that masscan and nmap both fix anyway.
//
// Used by the ingest path to answer "did this scan actually cover UDP/53?",
// which is what separates "this port closed" from "this port simply wasn't
// in this scan's range" - see the port.closed webhook. Protocol is part of
// that question, not a detail: a TCP scan of port 53 says nothing at all
// about UDP/53, and host_port_observations keys on (port, protocol) for
// exactly that reason.

const MAX_PORT = 65535;

export type PortProtocol = "tcp" | "udp";

// Ranges are stored rather than expanded: a spec of "1-65535" is entirely
// normal here, and expanding it into a 65k-entry Set on every ingest
// request would be pure waste when the only question ever asked is
// membership.
export interface PortSpec {
  singles: Set<string>; // "tcp:443"
  ranges: Array<{ protocol: PortProtocol; lo: number; hi: number }>;
}

function key(protocol: PortProtocol, port: number): string {
  return `${protocol}:${port}`;
}

// Returns null for anything it can't parse rather than throwing or
// guessing. Callers treat null as "unknown coverage" and fall back to the
// conservative behavior, so a spec form this doesn't understand can never
// cause a false "port closed" claim.
export function parsePortSpec(spec: string): PortSpec | null {
  const singles = new Set<string>();
  const ranges: PortSpec["ranges"] = [];
  const trimmed = spec.trim();
  if (trimmed === "") return null;

  for (const rawPart of trimmed.split(",")) {
    let part = rawPart.trim();
    if (part === "") continue;

    // A "U:"/"T:" prefix applies to that comma-separated part only,
    // exactly as masscan and nmap read it - "U:53,80" is UDP/53 plus
    // TCP/80, not two UDP ports. Bare parts are TCP, which is what every
    // spec written before UDP scanning existed means.
    let protocol: PortProtocol = "tcp";
    if (part.length > 2 && part[1] === ":") {
      const p = part[0].toLowerCase();
      if (p === "u") protocol = "udp";
      else if (p !== "t") return null;
      part = part.slice(2);
    }

    const dash = part.indexOf("-");
    if (dash > 0) {
      const lo = Number(part.slice(0, dash).trim());
      const hi = Number(part.slice(dash + 1).trim());
      if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 1 || hi > MAX_PORT || lo > hi) return null;
      ranges.push({ protocol, lo, hi });
    } else {
      const port = Number(part);
      if (!Number.isInteger(port) || port < 1 || port > MAX_PORT) return null;
      singles.add(key(protocol, port));
    }
  }

  if (singles.size === 0 && ranges.length === 0) return null;
  return { singles, ranges };
}

export function portSpecCovers(spec: PortSpec, port: number, protocol: string): boolean {
  // Anything not explicitly udp counts as tcp, including an empty string:
  // masscan always sets a protocol, but an observation row written by an
  // older build might not, and defaulting to tcp matches what every such
  // row actually was.
  const proto: PortProtocol = protocol.toLowerCase() === "udp" ? "udp" : "tcp";
  if (spec.singles.has(key(proto, port))) return true;
  return spec.ranges.some((r) => r.protocol === proto && port >= r.lo && port <= r.hi);
}
