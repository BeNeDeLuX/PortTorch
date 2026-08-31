import { describe, expect, it } from "vitest";
import {
  cidrToRange,
  coveredFraction,
  intToIPv4,
  ipv4ToInt,
  normaliseCidr,
  parseTargetSpecRanges,
  rangesOverlap,
} from "./ipRange";

describe("ipv4ToInt / intToIPv4", () => {
  it("round-trips the whole address space, including the top half", () => {
    // The top half is where a naive implementation using bitwise ops on
    // signed 32-bit ints goes negative.
    for (const ip of ["0.0.0.0", "10.0.0.5", "192.168.1.1", "255.255.255.255", "240.0.0.1"]) {
      expect(intToIPv4(ipv4ToInt(ip))).toBe(ip);
    }
    expect(ipv4ToInt("255.255.255.255")).toBe(4294967295);
  });
});

describe("cidrToRange", () => {
  it("expands a CIDR to its full inclusive span", () => {
    expect(cidrToRange("10.0.0.0/24")).toEqual({ start: ipv4ToInt("10.0.0.0"), end: ipv4ToInt("10.0.0.255") });
    expect(cidrToRange("10.0.0.5/32")).toEqual({ start: ipv4ToInt("10.0.0.5"), end: ipv4ToInt("10.0.0.5") });
    expect(cidrToRange("0.0.0.0/0")).toEqual({ start: 0, end: 4294967295 });
  });

  it("normalises a CIDR whose address is not the network address", () => {
    // masscan and nmap both accept 10.0.0.37/24 and treat it as 10.0.0.0/24.
    expect(cidrToRange("10.0.0.37/24")).toEqual(cidrToRange("10.0.0.0/24"));
  });

  it("rejects malformed input", () => {
    expect(cidrToRange("10.0.0.0")).toBeNull();
    expect(cidrToRange("10.0.0.0/33")).toBeNull();
    expect(cidrToRange("not-an-ip/24")).toBeNull();
    expect(cidrToRange("2001:db8::/32")).toBeNull();
  });
});

describe("normaliseCidr", () => {
  it("clears host bits, which Postgres's cidr type refuses to do itself", () => {
    // Postgres errors with "invalid cidr value" on the left-hand forms,
    // but masscan/nmap accept them - so they have to be normalised before
    // they ever reach the database.
    expect(normaliseCidr("10.0.0.37/24")).toBe("10.0.0.0/24");
    expect(normaliseCidr("192.168.1.255/16")).toBe("192.168.0.0/16");
    expect(normaliseCidr("10.0.0.5/32")).toBe("10.0.0.5/32");
  });

  it("leaves an already-canonical CIDR untouched", () => {
    expect(normaliseCidr("10.0.0.0/24")).toBe("10.0.0.0/24");
    expect(normaliseCidr("0.0.0.0/0")).toBe("0.0.0.0/0");
  });

  it("returns null for anything that is not an IPv4 CIDR", () => {
    expect(normaliseCidr("10.0.0.1")).toBeNull();
    expect(normaliseCidr("2001:db8::/32")).toBeNull();
    expect(normaliseCidr("10.0.0.0/33")).toBeNull();
  });
});

describe("parseTargetSpecRanges", () => {
  it("handles the three IPv4 forms masscan accepts, including comma lists", () => {
    expect(parseTargetSpecRanges("10.0.0.5")).toEqual([{ start: ipv4ToInt("10.0.0.5"), end: ipv4ToInt("10.0.0.5") }]);
    expect(parseTargetSpecRanges("10.0.0.0/30")).toEqual([
      { start: ipv4ToInt("10.0.0.0"), end: ipv4ToInt("10.0.0.3") },
    ]);
    expect(parseTargetSpecRanges("10.0.0.1-10.0.0.10")).toEqual([
      { start: ipv4ToInt("10.0.0.1"), end: ipv4ToInt("10.0.0.10") },
    ]);
    expect(parseTargetSpecRanges("10.0.0.1, 10.0.1.0/24")).toHaveLength(2);
  });

  it("returns null - not an empty list - for anything it cannot interpret", () => {
    // A hostname target is resolved on the scanner, so the webserver
    // genuinely does not know which addresses it covered.
    expect(parseTargetSpecRanges("db.internal")).toBeNull();
    expect(parseTargetSpecRanges("2001:db8::1")).toBeNull();
    expect(parseTargetSpecRanges("10.0.0.10-10.0.0.1")).toBeNull(); // reversed
    expect(parseTargetSpecRanges("")).toBeNull();
    // One bad part poisons the whole spec rather than being skipped: a
    // partially-understood spec would understate coverage.
    expect(parseTargetSpecRanges("10.0.0.1, db.internal")).toBeNull();
  });
});

describe("rangesOverlap", () => {
  it("treats touching-but-not-overlapping ranges as disjoint", () => {
    const a = { start: 10, end: 20 };
    expect(rangesOverlap(a, { start: 20, end: 30 })).toBe(true);
    expect(rangesOverlap(a, { start: 21, end: 30 })).toBe(false);
    expect(rangesOverlap(a, { start: 0, end: 9 })).toBe(false);
    expect(rangesOverlap(a, { start: 12, end: 13 })).toBe(true); // fully inside
  });
});

describe("coveredFraction", () => {
  const slash24 = cidrToRange("10.0.0.0/24")!;

  it("is 0 when nothing overlaps and 1 when the whole range is swept", () => {
    expect(coveredFraction(slash24, [])).toBe(0);
    expect(coveredFraction(slash24, [cidrToRange("10.1.0.0/24")!])).toBe(0);
    expect(coveredFraction(slash24, [cidrToRange("10.0.0.0/24")!])).toBe(1);
    // A larger sweep containing the range covers all of it.
    expect(coveredFraction(slash24, [cidrToRange("10.0.0.0/16")!])).toBe(1);
  });

  it("counts a single host inside a /24 as 1/256, not as covered", () => {
    // The whole point: a targeted rescan of one host must not make a /24
    // look scanned.
    expect(coveredFraction(slash24, [cidrToRange("10.0.0.5/32")!])).toBeCloseTo(1 / 256, 10);
  });

  it("counts overlapping sweeps once instead of exceeding 100%", () => {
    const halves = [cidrToRange("10.0.0.0/25")!, cidrToRange("10.0.0.0/25")!];
    expect(coveredFraction(slash24, halves)).toBeCloseTo(0.5, 10);
    expect(coveredFraction(slash24, [cidrToRange("10.0.0.0/24")!, cidrToRange("10.0.0.0/25")!])).toBe(1);
  });

  it("merges adjacent ranges with no gap between them", () => {
    // .0-.127 and .128-.255 are adjacent, not overlapping - together they
    // are the full /24.
    expect(coveredFraction(slash24, [cidrToRange("10.0.0.0/25")!, cidrToRange("10.0.0.128/25")!])).toBe(1);
  });

  it("clips a sweep that only partially overlaps the range", () => {
    expect(
      coveredFraction(slash24, [{ start: ipv4ToInt("9.255.255.0"), end: ipv4ToInt("10.0.0.127") }])
    ).toBeCloseTo(0.5, 10);
  });

  it("handles a /8 without precision loss", () => {
    const slash8 = cidrToRange("10.0.0.0/8")!;
    expect(coveredFraction(slash8, [cidrToRange("10.0.0.0/9")!])).toBeCloseTo(0.5, 10);
    expect(coveredFraction(slash8, [cidrToRange("10.0.0.0/24")!])).toBeCloseTo(256 / 16777216, 12);
  });
});
