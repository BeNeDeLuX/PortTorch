import type { SubnetEntry } from "../api";

// How exposed a subnet is, as one level, so the map and the table colour
// and sort it the same way. KEV outranks CVSS: a confirmed-exploited
// finding is more urgent than an unexploited critical one - the same
// ordering the Vulnerabilities page's default sort uses.
export type SubnetRisk = "kev" | "critical" | "high" | "medium" | "low" | "none";

export const RISK_LEVELS: SubnetRisk[] = ["kev", "critical", "high", "medium", "low", "none"];

export const RISK_LABELS: Record<SubnetRisk, string> = {
  kev: "Known exploited (KEV)",
  critical: "Critical CVE (CVSS 9+)",
  high: "High CVE (CVSS 7+)",
  medium: "Medium CVE (CVSS 4+)",
  low: "Low CVE",
  // Deliberately not "safe": it means nothing matched the CVE cache,
  // which is a statement about what is known, not that nothing is there.
  none: "No known CVEs",
};

export function subnetRisk(s: Pick<SubnetEntry, "kevHosts" | "maxCvss" | "hostsWithCves">): SubnetRisk {
  if (s.kevHosts > 0) return "kev";
  if (s.hostsWithCves === 0 || s.maxCvss === null) return s.hostsWithCves > 0 ? "low" : "none";
  if (s.maxCvss >= 9) return "critical";
  if (s.maxCvss >= 7) return "high";
  if (s.maxCvss >= 4) return "medium";
  return "low";
}

// Lower is worse, so an ascending sort puts the worst subnet first.
export function riskRank(r: SubnetRisk): number {
  return RISK_LEVELS.indexOf(r);
}

export interface SixteenGroup {
  // The /16 this block of /24s belongs to, e.g. "10.20.0.0/16".
  parent: string;
  // 256 slots, one per third octet; null where no host is known.
  cells: (SubnetEntry | null)[];
  subnets: number;
  hosts: number;
  openPorts: number;
  newHosts: number;
  // Worst-of across its /24s, in the shape subnetRisk reads, so a /16
  // is ranked and coloured by exactly the rule a single /24 is.
  hostsWithCves: number;
  kevHosts: number;
  maxCvss: number | null;
}

// Lays IPv4 /24s out as one 16x16 map per /16, so where in an address
// block the hosts actually sit is visible at a glance - including the
// empty stretches, which is half of what a map is for. Anything that is
// not an IPv4 /24 (IPv6 /64s) is returned separately rather than
// squeezed into a grid that has no meaning for it.
export function groupIntoSixteens(subnets: SubnetEntry[]): { groups: SixteenGroup[]; other: SubnetEntry[] } {
  const byParent = new Map<string, SixteenGroup>();
  const other: SubnetEntry[] = [];
  for (const s of subnets) {
    const m = s.family === 4 ? /^(\d+)\.(\d+)\.(\d+)\.0\/24$/.exec(s.subnet) : null;
    if (!m) {
      other.push(s);
      continue;
    }
    const parent = `${m[1]}.${m[2]}.0.0/16`;
    let group = byParent.get(parent);
    if (!group) {
      group = {
        parent,
        cells: new Array(256).fill(null),
        subnets: 0,
        hosts: 0,
        openPorts: 0,
        newHosts: 0,
        hostsWithCves: 0,
        kevHosts: 0,
        maxCvss: null,
      };
      byParent.set(parent, group);
    }
    group.cells[Number(m[3])] = s;
    group.subnets += 1;
    group.hosts += s.hosts;
    group.openPorts += s.openPorts;
    group.newHosts += s.newHosts;
    group.hostsWithCves += s.hostsWithCves;
    group.kevHosts += s.kevHosts;
    if (s.maxCvss !== null && (group.maxCvss === null || s.maxCvss > group.maxCvss)) group.maxCvss = s.maxCvss;
  }
  const groups = [...byParent.values()].sort((a, b) => compareSubnets(a.parent, b.parent));
  return { groups, other };
}

export interface EightGroup {
  // The /8 a set of /16s belongs to, e.g. "10.0.0.0/8".
  parent: string;
  // 256 slots, one per second octet; null where no host is known.
  cells: (SixteenGroup | null)[];
  networks: number;
  hosts: number;
}

// The level above groupIntoSixteens, for a fleet spread over so many /16s
// that one card each stops being readable: one 16x16 map per /8, one
// square per /16, laid out exactly like the /24 maps beneath it.
export function groupIntoEights(sixteens: SixteenGroup[]): EightGroup[] {
  const byParent = new Map<string, EightGroup>();
  for (const g of sixteens) {
    const [a, b] = g.parent.split(".");
    const parent = `${a}.0.0.0/8`;
    let eight = byParent.get(parent);
    if (!eight) {
      eight = { parent, cells: new Array(256).fill(null), networks: 0, hosts: 0 };
      byParent.set(parent, eight);
    }
    eight.cells[Number(b)] = g;
    eight.networks += 1;
    eight.hosts += g.hosts;
  }
  return [...byParent.values()].sort((x, y) => compareSubnets(x.parent, y.parent));
}

// Matches what someone types to find a network: "10.46", "10.46.", or
// the CIDR itself. Octet-aligned, so "10.4" does not match 10.46.0.0/16 -
// the same whole-octet rule the ip: search applies.
export function matchesNetworkFilter(parent: string, filter: string): boolean {
  const f = filter.trim().replace(/\.$/, "");
  if (!f) return true;
  if (parent === f) return true;
  const address = parent.split("/")[0];
  return address === f || address.startsWith(`${f}.`);
}

// Numeric order for IPv4 ("10.0.2.0/24" before "10.0.10.0/24"), with IPv6
// after every IPv4 subnet - the same convention the Dashboard's IP sort
// follows, since the two families have no shared order.
export function compareSubnets(a: string, b: string): number {
  const va = ipv4Value(a);
  const vb = ipv4Value(b);
  if (va !== null && vb !== null) return va - vb;
  if (va !== null) return -1;
  if (vb !== null) return 1;
  return a.localeCompare(b);
}

function ipv4Value(subnet: string): number | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)/.exec(subnet);
  if (!m) return null;
  return ((Number(m[1]) * 256 + Number(m[2])) * 256 + Number(m[3])) * 256 + Number(m[4]);
}

// A cell's fill strength for a count, 0 for nothing. A non-zero value
// never drops below a visible floor, so one host in a sea of empties
// still reads as "something is here". Logarithmic, because host counts
// per network are heavily skewed: on a linear scale one busy /24 with
// 250 hosts paints every network with five hosts the same pale shade.
export function intensity(value: number, max: number): number {
  if (value <= 0 || max <= 0) return 0;
  if (max <= 1) return 1;
  return 0.2 + 0.8 * Math.min(1, Math.log(value) / Math.log(max));
}
