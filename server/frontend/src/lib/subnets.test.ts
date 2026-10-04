import { describe, expect, it } from "vitest";
import type { SubnetEntry } from "../api";
import {
  compareSubnets,
  groupIntoEights,
  groupIntoSixteens,
  intensity,
  matchesNetworkFilter,
  riskRank,
  subnetRisk,
} from "./subnets";

function entry(subnet: string, over: Partial<SubnetEntry> = {}): SubnetEntry {
  return {
    subnet,
    family: subnet.includes(":") ? 6 : 4,
    hosts: 1,
    openPorts: 1,
    hostsWithCves: 0,
    newHosts: 0,
    criticalHosts: 0,
    kevHosts: 0,
    maxCvss: null,
    lastSeenAt: null,
    ...over,
  };
}

describe("subnetRisk", () => {
  it("ranks KEV above any CVSS score", () => {
    expect(subnetRisk({ kevHosts: 1, maxCvss: 5, hostsWithCves: 1 })).toBe("kev");
    expect(riskRank("kev")).toBeLessThan(riskRank("critical"));
  });

  it("maps CVSS onto the same thresholds as the CVE badges", () => {
    expect(subnetRisk({ kevHosts: 0, maxCvss: 9.8, hostsWithCves: 2 })).toBe("critical");
    expect(subnetRisk({ kevHosts: 0, maxCvss: 7.0, hostsWithCves: 2 })).toBe("high");
    expect(subnetRisk({ kevHosts: 0, maxCvss: 4.3, hostsWithCves: 2 })).toBe("medium");
    expect(subnetRisk({ kevHosts: 0, maxCvss: 2.1, hostsWithCves: 2 })).toBe("low");
  });

  it("keeps a CVE without a score visible rather than calling it clean", () => {
    // NVD publishes CVEs with no CVSS metric at all - such a subnet still
    // has a known finding.
    expect(subnetRisk({ kevHosts: 0, maxCvss: null, hostsWithCves: 1 })).toBe("low");
    expect(subnetRisk({ kevHosts: 0, maxCvss: null, hostsWithCves: 0 })).toBe("none");
  });
});

describe("groupIntoSixteens", () => {
  it("places each /24 at its third octet within its /16, and keeps IPv6 aside", () => {
    const { groups, other } = groupIntoSixteens([
      entry("10.20.5.0/24", { hosts: 3 }),
      entry("10.20.200.0/24", { hosts: 2 }),
      entry("10.3.0.0/24"),
      entry("2001:db8::/64"),
    ]);
    expect(groups.map((g) => g.parent)).toEqual(["10.3.0.0/16", "10.20.0.0/16"]);
    const twenty = groups[1];
    expect(twenty.cells).toHaveLength(256);
    expect(twenty.cells[5]?.subnet).toBe("10.20.5.0/24");
    expect(twenty.cells[200]?.subnet).toBe("10.20.200.0/24");
    expect(twenty.cells[6]).toBeNull();
    expect(twenty.hosts).toBe(5);
    expect(twenty.subnets).toBe(2);
    expect(other.map((o) => o.subnet)).toEqual(["2001:db8::/64"]);
  });

  it("rolls each /16 up into the same risk shape a /24 has", () => {
    const { groups } = groupIntoSixteens([
      entry("10.20.1.0/24", { hosts: 2, openPorts: 5, hostsWithCves: 1, maxCvss: 7.5 }),
      entry("10.20.2.0/24", { hosts: 1, openPorts: 1, hostsWithCves: 1, maxCvss: 9.8, kevHosts: 1 }),
    ]);
    expect(groups[0]).toMatchObject({ hosts: 3, openPorts: 6, hostsWithCves: 2, kevHosts: 1, maxCvss: 9.8 });
    expect(subnetRisk(groups[0])).toBe("kev");
  });

  it("does not grid a grouping wider than /24", () => {
    // The map is per /24 by construction; a /20 has no single cell.
    const { groups, other } = groupIntoSixteens([entry("10.20.16.0/20")]);
    expect(groups).toHaveLength(0);
    expect(other).toHaveLength(1);
  });
});

describe("groupIntoEights", () => {
  it("places each /16 at its second octet within its /8", () => {
    const { groups } = groupIntoSixteens([
      entry("10.46.1.0/24", { hosts: 4 }),
      entry("10.200.9.0/24", { hosts: 1 }),
      entry("172.16.0.0/24", { hosts: 2 }),
    ]);
    const eights = groupIntoEights(groups);
    expect(eights.map((e) => e.parent)).toEqual(["10.0.0.0/8", "172.0.0.0/8"]);
    expect(eights[0].cells[46]?.parent).toBe("10.46.0.0/16");
    expect(eights[0].cells[200]?.parent).toBe("10.200.0.0/16");
    expect(eights[0].cells[47]).toBeNull();
    expect(eights[0]).toMatchObject({ networks: 2, hosts: 5 });
  });
});

describe("matchesNetworkFilter", () => {
  it("matches whole octets only", () => {
    expect(matchesNetworkFilter("10.46.0.0/16", "")).toBe(true);
    expect(matchesNetworkFilter("10.46.0.0/16", "10")).toBe(true);
    expect(matchesNetworkFilter("10.46.0.0/16", "10.46")).toBe(true);
    expect(matchesNetworkFilter("10.46.0.0/16", "10.46.")).toBe(true);
    expect(matchesNetworkFilter("10.46.0.0/16", "10.46.0.0/16")).toBe(true);
    expect(matchesNetworkFilter("10.46.0.0/16", "10.4")).toBe(false);
    expect(matchesNetworkFilter("10.46.0.0/16", "10.47")).toBe(false);
  });
});

describe("compareSubnets", () => {
  it("orders IPv4 numerically and IPv6 after it", () => {
    const sorted = ["2001:db8::/64", "10.0.10.0/24", "10.0.2.0/24", "9.0.0.0/24"].sort(compareSubnets);
    expect(sorted).toEqual(["9.0.0.0/24", "10.0.2.0/24", "10.0.10.0/24", "2001:db8::/64"]);
  });
});

describe("intensity", () => {
  it("is zero only for nothing, and never invisible otherwise", () => {
    expect(intensity(0, 50)).toBe(0);
    expect(intensity(1, 1000)).toBeGreaterThanOrEqual(0.2);
    expect(intensity(50, 50)).toBe(1);
    expect(intensity(1, 1)).toBe(1);
  });

  it("is logarithmic, so one full network does not wash out the rest", () => {
    // Linear, 5 of 250 would be 0.216 - indistinguishable from 1 host.
    expect(intensity(5, 250)).toBeGreaterThan(0.4);
    expect(intensity(5, 250)).toBeGreaterThan(intensity(1, 250));
    expect(intensity(50, 250)).toBeGreaterThan(intensity(5, 250));
  });
});
