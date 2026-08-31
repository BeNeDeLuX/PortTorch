import net from "net";

// Closed IPv4 interval [start, end], both inclusive, as unsigned 32-bit
// numbers. JS numbers hold 2^32 exactly, so no BigInt is needed.
export interface IPv4Range {
  start: number;
  end: number;
}

export function ipv4ToInt(value: string): number {
  return value.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

export function intToIPv4(value: number): string {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

// A CIDR's full address span - network and broadcast address included.
// Coverage is about "did a scanner sweep these addresses", not about
// which of them a host could usefully be assigned, so nothing is
// subtracted here.
export function cidrToRange(value: string): IPv4Range | null {
  const idx = value.indexOf("/");
  if (idx === -1) return null;
  const address = value.slice(0, idx);
  const prefix = Number(value.slice(idx + 1));
  if (net.isIP(address) !== 4) return null;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const size = 2 ** (32 - prefix);
  const base = Math.floor(ipv4ToInt(address) / size) * size;
  return { start: base, end: base + size - 1 };
}

// Parses one scan target spec into the address ranges it actually covers.
//
// Returns null - not an empty list - for anything this can't interpret
// exactly: a DNS hostname (resolved scanner-side, so the webserver has no
// idea what it pointed at), an IPv6 target, a malformed part. Null means
// "unknown", and every caller must treat it as such rather than as "covers
// nothing": claiming a range was never scanned because the spec was a
// hostname would be worse than admitting the spec is opaque.
export function parseTargetSpecRanges(spec: string): IPv4Range[] | null {
  const parts = spec
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (parts.length === 0) return null;

  const ranges: IPv4Range[] = [];
  for (const part of parts) {
    if (net.isIP(part) === 4) {
      const value = ipv4ToInt(part);
      ranges.push({ start: value, end: value });
      continue;
    }
    if (part.includes("/")) {
      const cidr = cidrToRange(part);
      if (!cidr) return null;
      ranges.push(cidr);
      continue;
    }
    const dash = part.indexOf("-");
    if (dash > 0) {
      const start = part.slice(0, dash);
      const end = part.slice(dash + 1);
      if (net.isIP(start) !== 4 || net.isIP(end) !== 4) return null;
      const lo = ipv4ToInt(start);
      const hi = ipv4ToInt(end);
      if (lo > hi) return null;
      ranges.push({ start: lo, end: hi });
      continue;
    }
    return null;
  }
  return ranges;
}

// Canonical form of an IPv4 CIDR: host bits cleared, so "10.0.0.37/24"
// becomes "10.0.0.0/24".
//
// This is not cosmetic. Postgres's cidr type *rejects* a value with host
// bits set ("invalid cidr value") rather than normalising it, while
// masscan and nmap both accept that form happily - so a spec an operator
// can legitimately type into a scan target would be a 500 on the way into
// monitored_networks without this. Returns null for anything that isn't
// an IPv4 CIDR at all.
export function normaliseCidr(value: string): string | null {
  const range = cidrToRange(value);
  if (!range) return null;
  const prefix = value.slice(value.indexOf("/"));
  return intToIPv4(range.start) + prefix;
}

export function rangesOverlap(a: IPv4Range, b: IPv4Range): boolean {
  return a.start <= b.end && b.start <= a.end;
}

// How much of `network` the given ranges cover, as a fraction in [0, 1].
//
// The ranges are clipped to the network and merged before measuring, so
// overlapping scans (the normal case - a daily /24 sweep plus a targeted
// single-host rescan inside it) count the shared addresses once rather
// than reporting more than 100%.
export function coveredFraction(network: IPv4Range, ranges: IPv4Range[]): number {
  const size = network.end - network.start + 1;
  if (size <= 0) return 0;

  const clipped = ranges
    .filter((r) => rangesOverlap(r, network))
    .map((r) => ({ start: Math.max(r.start, network.start), end: Math.min(r.end, network.end) }))
    .sort((a, b) => a.start - b.start);
  if (clipped.length === 0) return 0;

  let covered = 0;
  let current = clipped[0];
  for (const range of clipped.slice(1)) {
    // +1 because the intervals are closed: [1,2] and [3,4] are adjacent,
    // not disjoint, and together cover 1-4 without a gap.
    if (range.start <= current.end + 1) {
      current = { start: current.start, end: Math.max(current.end, range.end) };
    } else {
      covered += current.end - current.start + 1;
      current = range;
    }
  }
  covered += current.end - current.start + 1;

  return covered / size;
}
