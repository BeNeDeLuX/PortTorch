import { describe, expect, it } from "vitest";
import { compareVersions, isComparableVersion, parseSysDescr } from "./firmware";

describe("parseSysDescr", () => {
  it.each([
    // Real lines from a live deployment.
    ["UAP-AC-Pro-Gen2 6.8.2.15592\n  System uptime: 72d22h08m54.00s (630053400 timeticks)", "UAP-AC-Pro-Gen2", "6.8.2.15592"],
    ["USW-Enterprise-8-PoE, 7.5.15.17146", "USW-Enterprise-8-PoE", "7.5.15.17146"],
    ["U6-Pro 6.8.2.15592", "U6-Pro", "6.8.2.15592"],
    // The common shapes of other vendors.
    ["Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE7, RELEASE SOFTWARE (fc2)", "Cisco IOS", "12.2(55)SE7"],
    ["Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(8), RELEASE SOFTWARE", "Cisco NX-OS", "9.3(8)"],
    ["Linux fw01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64", "Linux kernel", "5.15.0-91-generic"],
    ["Hardware: Intel64 Family 6 Model 85 - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)", "Windows", "6.3.17763"],
  ])("%s", (line, product, version) => {
    expect(parseSysDescr(line)).toEqual({ product, version });
  });

  it("reads nothing without a version", () => {
    expect(parseSysDescr("HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153")).toBeNull();
    expect(parseSysDescr("Main office switch")).toBeNull();
    expect(parseSysDescr("6.8.2")).toBeNull();
    expect(parseSysDescr("")).toBeNull();
  });
});

describe("compareVersions", () => {
  it("compares numerically", () => {
    expect(compareVersions("7.5.15.17146", "7.5.10.17129")).toBeGreaterThan(0);
    expect(compareVersions("7.5.9", "7.5.15")).toBeLessThan(0);
    expect(compareVersions("6.8.2.15592", "6.8.2.15592")).toBe(0);
    expect(compareVersions("12.2(55)SE7", "12.2(55)SE12")).toBeLessThan(0);
  });
  it("only calls dotted versions comparable", () => {
    expect(isComparableVersion("7.5.15.17146")).toBe(true);
    expect(isComparableVersion("12.2(55)SE7")).toBe(true);
    expect(isComparableVersion("8.4p1")).toBe(true);
    expect(compareVersions("8.4p1", "9.6p1")).toBeLessThan(0);
    expect(isComparableVersion("3.X - 4.X")).toBe(false);
    expect(isComparableVersion("9.6.0 or later")).toBe(false);
  });
});
