import { describe, expect, it } from "vitest";
import { udpProbeInScope, udpProbesInScope } from "./udpProbes";

// The same cases as the scanner's TestFixedUDPProbeInScope.
describe("udpProbeInScope", () => {
  it.each([
    ["22", 161, false],
    ["1-10000", 161, true],
    ["1-1024", 1900, false],
    ["22,U:161", 161, true],
    ["T:1-10000", 161, false],
    ["T:22,U:53", 53, true],
    ["", 161, false],
  ] as const)("%s covers %d: %s", (spec, port, want) => {
    expect(udpProbeInScope(spec, port)).toBe(want);
  });

  it("lists the probes a spec triggers", () => {
    expect(udpProbesInScope("1-10000").map((p) => p.port)).toEqual([53, 161, 623, 1900]);
  });
});
