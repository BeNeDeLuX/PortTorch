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
