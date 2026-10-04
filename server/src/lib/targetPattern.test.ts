import { describe, expect, it } from "vitest";
import { parseTargetSpecRanges } from "./ipRange";
import {
  countExcludePattern,
  expandExcludePattern,
  expandTargetPattern,
  isTargetPattern,
  parseExcludePatternValue,
} from "./targetPattern";

function addresses(spec: string): number[] {
  const out: number[] = [];
  for (const r of parseTargetSpecRanges(spec) ?? []) for (let a = r.start; a <= r.end; a++) out.push(a);
  return out;
}

function expand(spec: string): string {
  const r = expandTargetPattern(spec);
  if (!r.ok) throw new Error(r.error);
  return r.spec;
}

const lastOctet = (a: number) => a & 255;

describe("expandTargetPattern", () => {
  it("leaves a spec without pattern syntax exactly as typed", () => {
    for (const spec of ["10.0.0.0/24", "10.0.0.1-10.0.0.9, 10.0.1.5", "web-01.internal", "2001:db8::1,2001:db8::2"]) {
      expect(expandTargetPattern(spec)).toEqual({ ok: true, spec, expanded: false, addresses: null });
      expect(isTargetPattern(spec)).toBe(false);
    }
  });

  it("scans a /16 except .2 and .4 in every /24", () => {
    const result = expandTargetPattern("10.46.0.0/16 !*.2 !*.4");
    expect(result).toMatchObject({ ok: true, expanded: true, addresses: 65536 - 512 });
    const all = addresses(expand("10.46.0.0/16 !*.2 !*.4"));
    expect(all).toHaveLength(65536 - 512);
    expect(all.some((a) => lastOctet(a) === 2 || lastOctet(a) === 4)).toBe(false);
    // Commas and spaces separate tokens alike.
    expect(expand("10.46.0.0/16, !*.2, !*.4")).toBe(expand("10.46.0.0/16 !*.2 !*.4"));
  });

  it("scans only the .125 in each /24", () => {
    const all = addresses(expand("10.46.*.125"));
    expect(all).toHaveLength(256);
    expect(all.every((a) => lastOctet(a) === 125 && a >>> 16 === (10 << 8) + 46)).toBe(true);
  });

  it("takes octet ranges, range and CIDR exclusions, and longer suffixes", () => {
    expect(addresses(expand("10.46.1-2.10-11"))).toHaveLength(4);
    expect(addresses(expand("10.46.0.0/22 !10.46.1.0/24"))).toHaveLength(768);
    // Last two octets: .0.1 in every /16 - here exactly one address.
    expect(addresses(expand("10.46.0.0/16 !*.0.1"))).toHaveLength(65535);
    expect(addresses(expand("10.46.0.0/24 !*.0-9"))).toHaveLength(246);
  });

  it("passes hostnames and IPv6 through, applying exclusions to IPv4 only", () => {
    const spec = expand("10.46.0.0/30 !*.1 web.internal 2001:db8::1");
    expect(spec).toBe("10.46.0.0,10.46.0.2-10.46.0.3,web.internal,2001:db8::1");
  });

  it("refuses what it cannot honour, with a reason", () => {
    for (const [spec, fragment] of [
      ["!*.2", "only excludes"],
      ["10.46.0.0/30 !*.0-3", "no address"],
      ["10.46.0.0/16 !nonsense", "not an address"],
      ["10.0.0.0/8 !*.2", "/12"],
      ["10.*.*.1", "KB"],
    ] as const) {
      const r = expandTargetPattern(spec);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain(fragment);
    }
  });
});

describe("pattern excludes", () => {
  it("parses the stored form and refuses what is not a pattern", () => {
    expect(parseExcludePatternValue("10.46.0.0/16 *.2")).toMatchObject({ scopeText: "10.46.0.0/16", patternText: "*.2" });
    expect("error" in parseExcludePatternValue("10.46.0.0/16")).toBe(true);
    expect("error" in parseExcludePatternValue("10.46.0.0/16 10.46.0.2")).toBe(true);
    expect("error" in parseExcludePatternValue("10.0.0.0/8 *.2")).toBe(true);
    expect("error" in parseExcludePatternValue("web.internal *.2")).toBe(true);
  });

  it("expands to the matching addresses inside its range, and nothing outside it", () => {
    const entries = expandExcludePattern("10.46.0.0/16 *.2");
    expect(entries).toHaveLength(256);
    expect(entries[0]).toBe("10.46.0.2");
    expect(entries[255]).toBe("10.46.255.2");
    expect(countExcludePattern("10.46.0.0/16 *.2")).toBe(256);
    // A run of matches comes back as one range, not 10 lines.
    expect(expandExcludePattern("10.46.5.0/24 *.0-9")).toEqual(["10.46.5.0-10.46.5.9"]);
  });
});
