import { describe, expect, it } from "vitest";
import { parseTargetSpecRanges } from "./ipRange";
import { ownerOf, partRate, splitTargetSpec, type SplitPart } from "./scanSplit";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";

function parts(spec: string, ids: string[]): SplitPart[] {
  const r = splitTargetSpec(spec, ids);
  if (!r.ok) throw new Error(r.error);
  return r.parts;
}

// Every address of every part, as numbers, for coverage checks.
function addressesOf(spec: string): number[] {
  const out: number[] = [];
  for (const r of parseTargetSpecRanges(spec) ?? []) for (let a = r.start; a <= r.end; a++) out.push(a);
  return out;
}

function ownerMap(ps: SplitPart[]): Map<number, string> {
  const m = new Map<number, string>();
  for (const p of ps) for (const a of addressesOf(p.targetSpec)) m.set(a, p.scannerAgentId);
  return m;
}

describe("splitTargetSpec", () => {
  it("leaves a single-scanner target exactly as typed", () => {
    expect(parts(" 10.0.0.0/24, web.internal ", [A])).toEqual([
      { scannerAgentId: A, targetSpec: "10.0.0.0/24, web.internal", addresses: null },
    ]);
  });

  it("covers every address exactly once, and spreads even one /24", () => {
    const ps = parts("10.0.0.0/24", [A, B, C]);
    const all = ps.flatMap((p) => addressesOf(p.targetSpec)).sort((x, y) => x - y);
    expect(all).toEqual(addressesOf("10.0.0.0/24"));
    // 16 /28 blocks across three scanners - all three get a share.
    expect(ps).toHaveLength(3);
    expect(ps.reduce((n, p) => n + (p.addresses ?? 0), 0)).toBe(256);
  });

  it("assigns an address the same way whatever the rest of the target is", () => {
    // The property that keeps host identity stable: 10.0.0.37 must land
    // on the same scanner in a /24 scan, a /16 scan and a scan of just a
    // few addresses around it.
    const small = ownerMap(parts("10.0.0.32-10.0.0.47", [A, B, C]));
    const mid = ownerMap(parts("10.0.0.0/24", [A, B, C]));
    const big = ownerMap(parts("10.0.0.0/16", [A, B, C]));
    for (let a = 0x0a000020; a <= 0x0a00002f; a++) {
      expect(mid.get(a)).toBe(small.get(a));
      expect(big.get(a)).toBe(small.get(a));
    }
  });

  it("does not depend on the order the scanners are chosen in", () => {
    expect(ownerMap(parts("10.1.0.0/20", [A, B, C]))).toEqual(ownerMap(parts("10.1.0.0/20", [C, A, B])));
  });

  it("moves only the blocks a newly added scanner wins", () => {
    const before = ownerMap(parts("10.2.0.0/20", [A, B]));
    const after = ownerMap(parts("10.2.0.0/20", [A, B, C]));
    for (const [addr, owner] of after) {
      // An address either stays where it was or moves to the newcomer -
      // never from A to B, which would create a duplicate for nothing.
      if (owner !== C) expect(owner).toBe(before.get(addr));
    }
  });

  it("is roughly balanced", () => {
    const ps = parts("10.3.0.0/16", [A, B, C]);
    for (const p of ps) {
      expect(p.addresses!).toBeGreaterThan(65536 / 3 * 0.85);
      expect(p.addresses!).toBeLessThan(65536 / 3 * 1.15);
    }
  });

  it("assigns hostnames and IPv6 addresses whole", () => {
    const ps = parts("10.4.0.0/28,web.internal,2001:DB8::1", [A, B]);
    const joined = ps.map((p) => p.targetSpec).join(",");
    expect(joined.split(",").filter((t) => t === "web.internal")).toHaveLength(1);
    expect(joined).toContain("2001:db8::1");
    expect(ps.find((p) => p.targetSpec.includes("web.internal"))?.addresses).toBeNull();
    expect(ownerOf("u:web.internal", [A, B])).toBe(ownerOf("u:web.internal", [B, A]));
  });

  it("keeps every part short enough for one masscan argument", () => {
    // A /14 at /28 granularity would scatter into far too many ranges, so
    // the split falls back to coarser blocks rather than failing.
    const r = splitTargetSpec("10.0.0.0/14", [A, B, C]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.blockPrefix).not.toBe(28);
      for (const p of r.parts) expect(p.targetSpec.length).toBeLessThanOrEqual(65536);
    }
  });

  it("collapses duplicate scanner ids", () => {
    expect(parts("10.5.0.0/24", [A, A])).toHaveLength(1);
  });
});

describe("partRate", () => {
  it("divides a total rate across the parts only when asked to", () => {
    expect(partRate(3000, 3, true)).toBe(1000);
    expect(partRate(3000, 3, false)).toBe(3000);
    expect(partRate(2, 3, true)).toBe(1);
    expect(partRate(null, 3, true)).toBeNull();
  });
});
