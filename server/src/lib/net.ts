import net from "net";

// IPv4 CIDR only, matching the rest of the app's IPv4-only assumptions
// (masscan/nmap target IPv4 ranges, Dashboard's IP sort is octet-based).
export function isIPv4Cidr(value: string): boolean {
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(value);
  if (!match) return false;
  const prefix = Number(match[2]);
  return prefix >= 0 && prefix <= 32 && net.isIP(match[1]) === 4;
}

export function isIPv4(value: string): boolean {
  return net.isIP(value) === 4;
}

function ipv4ToInt(value: string): number {
  return value.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

// "startIp-endIp" (e.g. "10.0.0.1-10.0.0.10") - masscan's own target-spec
// grammar already accepts this form directly (in addition to a single IP
// or CIDR), and the scanner writes exclude values verbatim into masscan's
// --excludefile (pipeline/excludes.go) - so this only needed a validation
// change here, no scanner-side change at all.
export function isIPv4Range(value: string): boolean {
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(value);
  if (!match) return false;
  const [, start, end] = match;
  if (net.isIP(start) !== 4 || net.isIP(end) !== 4) return false;
  return ipv4ToInt(start) <= ipv4ToInt(end);
}

export function isIPv6(value: string): boolean {
  return net.isIP(value) === 6;
}

// IPv6 CIDR only - unlike an IPv4 CIDR/range scan *target* (a brute-force
// sweep, infeasible across IPv6's address space, see scanner's
// parseIPv6TargetList), a CIDR *exclude* is just a cheap containment check
// regardless of prefix width, so this stays deliberately simple: no
// "start-end" IPv6 range counterpart exists (or is needed) for the same
// reason a range scan target isn't supported either.
export function isIPv6Cidr(value: string): boolean {
  const idx = value.lastIndexOf("/");
  if (idx === -1) return false;
  const address = value.slice(0, idx);
  const prefix = Number(value.slice(idx + 1));
  return Number.isInteger(prefix) && prefix >= 0 && prefix <= 128 && net.isIP(address) === 6;
}

// A partly typed IPv4 address - "10.20.41", "172.16." - read as the block
// it names: one to three whole octets, each 0-255, at least one dot.
// The same rule the dashboard's quick search applies client-side
// (frontend/src/lib/quickSearch.ts), so `ip:10.20.41` in the search box
// and typing 10.20.41 into the quick search find the same hosts. A full
// four-octet address is not a prefix and returns null.
export function ipv4PrefixToCidr(query: string): string | null {
  const m = /^(\d{1,3})\.(?:(\d{1,3})\.?)?(?:(\d{1,3})\.?)?$/.exec(query.trim());
  if (!m) return null;
  const octets = [m[1], m[2], m[3]].filter((o): o is string => o !== undefined).map(Number);
  if (octets.some((o) => o > 255)) return null;
  return `${[...octets, 0, 0, 0].slice(0, 4).join(".")}/${octets.length * 8}`;
}

// What an explicit `ip:` search matches, or null when the value cannot be
// an address at all (which then matches nothing rather than falling back
// to free text - the prefix is a promise to search addresses only).
export type IpSearch =
  | { kind: "exact"; value: string }
  | { kind: "cidr"; value: string }
  | { kind: "prefix"; value: string };

export function parseIpSearch(value: string): IpSearch | null {
  const v = value.trim();
  if (!v) return null;
  if (net.isIP(v) !== 0) return { kind: "exact", value: v };
  if (isIPv4Cidr(v) || isIPv6Cidr(v)) return { kind: "cidr", value: v };
  const cidr = ipv4PrefixToCidr(v);
  if (cidr) return { kind: "cidr", value: cidr };
  // A partial IPv6 address - "2001:db8:", "fd00::1:" - has no block to
  // name, so it is matched as the leading text of the address.
  if (v.includes(":") && /^[0-9a-fA-F:]+$/.test(v)) return { kind: "prefix", value: v.toLowerCase() };
  return null;
}
