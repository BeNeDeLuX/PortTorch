import { describe, expect, it } from "vitest";
import { describeWindowsBuild } from "./windowsBuilds";

const NOW = new Date("2026-09-26T00:00:00Z");

describe("describeWindowsBuild", () => {
  it("names a build and reports it out of support once the date has passed", () => {
    const info = describeWindowsBuild("10.0.19045", NOW)!;
    expect(info.label).toBe("Windows 10 22H2");
    expect(info.outOfSupport).toBe(true);
    expect(info.detail).toContain("2025-10-14");
  });

  it("leaves a supported release alone", () => {
    const info = describeWindowsBuild("10.0.20348", NOW)!;
    expect(info.label).toBe("Windows Server 2022");
    expect(info.outOfSupport).toBe(false);
  });

  // The case the table exists to get right: one build, two editions, one
  // of them still supported. The build alone cannot say which this host
  // is, so calling it out of support would be a claim the data does not
  // carry.
  it("does not flag a shared build whose server edition is still supported", () => {
    const info = describeWindowsBuild("10.0.17763", NOW)!;
    expect(info.label).toBe("Windows 10 1809 / Windows Server 2019");
    expect(info.outOfSupport).toBe(false);
    expect(info.detail).toContain("does not say whether");
    // The half that did end is still stated.
    expect(info.detail).toContain("2020-11-10");
  });

  it("flags a shared build once both editions have ended", () => {
    const info = describeWindowsBuild("6.3.9600", NOW)!;
    expect(info.label).toBe("Windows 8.1 / Windows Server 2012 R2");
    expect(info.outOfSupport).toBe(true);
  });

  // An unknown build keeps its number rather than being given a guessed
  // name - the number is still the precise thing the scan found.
  it("shows an unknown build as itself", () => {
    const info = describeWindowsBuild("10.0.99999", NOW)!;
    expect(info.label).toBeNull();
    expect(info.outOfSupport).toBe(false);
    expect(info.detail).toContain("10.0.99999");
  });

  it("returns nothing when there is no build", () => {
    expect(describeWindowsBuild(null, NOW)).toBeNull();
  });

  // Support status is evaluated against the given date, so a release
  // becomes out of support on its own without anyone editing the table.
  it("treats a date still in the future as supported", () => {
    const early = describeWindowsBuild("10.0.19045", new Date("2025-01-01T00:00:00Z"))!;
    expect(early.outOfSupport).toBe(false);
  });
});
