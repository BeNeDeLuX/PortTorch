import { describe, expect, it } from "vitest";
import { countAddresses, countPorts, estimateScan, projectEnrichment } from "./estimate";

// The numbers here are the whole reason the feature exists - a /16 across
// every port has to come out as days, not as a shrug - so each target and
// port form is pinned rather than spot-checked.
describe("countAddresses", () => {
  it("counts every IPv4 target form masscan accepts", () => {
    expect(countAddresses("10.0.0.1")).toBe(1);
    expect(countAddresses("10.0.0.0/24")).toBe(256);
    expect(countAddresses("10.0.0.0/32")).toBe(1);
    expect(countAddresses("10.0.0.0/16")).toBe(65536);
    expect(countAddresses("10.0.0.1-10.0.0.10")).toBe(10);
    // Inclusive at both ends - a range of one address is one, not zero.
    expect(countAddresses("10.0.0.5-10.0.0.5")).toBe(1);
    expect(countAddresses("10.0.0.0/24,192.168.1.1,172.16.0.1-172.16.0.4")).toBe(256 + 1 + 4);
  });

  it("counts an IPv6 target list, which is always explicit addresses", () => {
    expect(countAddresses("2001:db8::1")).toBe(1);
    expect(countAddresses("2001:db8::1, 2001:db8::2")).toBe(2);
  });

  it("returns null for anything it cannot count exactly", () => {
    // Only the scanner's own DNS resolves this, at scan time - guessing 1
    // would be a claim rather than a count.
    expect(countAddresses("scanner.internal")).toBeNull();
    expect(countAddresses("")).toBeNull();
    expect(countAddresses("   ")).toBeNull();
    expect(countAddresses("10.0.0.10-10.0.0.1")).toBeNull();
    expect(countAddresses("999.0.0.1")).toBeNull();
  });
});

describe("countPorts", () => {
  it("counts singles, lists and ranges", () => {
    expect(countPorts("22")).toBe(1);
    expect(countPorts("22,80,443")).toBe(3);
    expect(countPorts("1-1000")).toBe(1000);
    expect(countPorts("1-65535")).toBe(65535);
  });

  it("counts each protocol separately - the same number twice is two probes", () => {
    expect(countPorts("T:80,U:80")).toBe(2);
    expect(countPorts("80,U:53,U:161")).toBe(3);
  });

  it("returns null for an unparseable spec rather than guessing", () => {
    expect(countPorts("not a port spec")).toBeNull();
    expect(countPorts("")).toBeNull();
  });
});

describe("estimateScan", () => {
  it("turns a /16 across every port into the number that stops a bad decision", () => {
    const e = estimateScan("172.16.0.0/16", "1-65535", 1000, "scanner");
    expect(e.addresses).toBe(65536);
    expect(e.ports).toBe(65535);
    expect(e.probes).toBe(65536 * 65535);
    // Just under 50 days at 1000 packets/second.
    expect(e.masscanSeconds).toBeCloseTo((65536 * 65535) / 1000, 0);
    expect(e.rateSource).toBe("scanner");
  });

  it("halves the time when the rate doubles", () => {
    const slow = estimateScan("10.0.0.0/24", "1-1000", 500, "override");
    const fast = estimateScan("10.0.0.0/24", "1-1000", 1000, "override");
    expect(slow.masscanSeconds).toBeCloseTo((fast.masscanSeconds ?? 0) * 2, 5);
  });

  it("reports nothing rather than a wrong number when either side is uncountable", () => {
    const e = estimateScan("scanner.internal", "1-1000", 1000, "default");
    expect(e.addresses).toBeNull();
    expect(e.probes).toBeNull();
    expect(e.masscanSeconds).toBeNull();
    // The port count is still known and still worth showing.
    expect(e.ports).toBe(1000);
  });
});

describe("projectEnrichment", () => {
  // Three /24 scans of one port at 1000 pps (0.256 s of discovery each),
  // each confirming 16 hosts in 160 s.
  const history = [1, 2, 3].map((n) => ({ targetSpec: `10.0.${n}.0/24`, portSpec: "22", durationSeconds: 160.256, hostsScanned: 16 }));

  it("projects hosts and time from the pooled ratios", () => {
    const p = projectEnrichment(history, 1024, 1000)!;
    expect(p.basedOnScans).toBe(3);
    expect(p.hitRate).toBeCloseTo(16 / 256, 6);
    expect(p.secondsPerHost).toBeCloseTo(10, 3);
    expect(p.expectedHosts).toBeCloseTo(64, 6);
    expect(p.enrichmentSeconds).toBeCloseTo(640, 1);
  });

  it("refuses to project from too little history", () => {
    expect(projectEnrichment(history.slice(0, 2), 1024, 1000)).toBeNull();
  });

  it("skips scans it cannot count, and a history that never found anything", () => {
    expect(projectEnrichment([...history.slice(0, 2), { targetSpec: "web.internal", portSpec: "22", durationSeconds: 99, hostsScanned: 1 }], 256, 1000)).toBeNull();
    expect(projectEnrichment(history.map((h) => ({ ...h, hostsScanned: 0 })), 256, 1000)).toBeNull();
  });
});
