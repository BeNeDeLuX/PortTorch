import { describe, expect, it } from "vitest";
import { parsePortSpec, portSpecCovers } from "./portSpec";

function covers(spec: string, port: number, protocol = "tcp"): boolean {
  const parsed = parsePortSpec(spec);
  if (!parsed) throw new Error(`expected ${spec} to parse`);
  return portSpecCovers(parsed, port, protocol);
}

describe("parsePortSpec", () => {
  it("handles single ports", () => {
    expect(covers("443", 443)).toBe(true);
    expect(covers("443", 444)).toBe(false);
  });

  it("handles comma-separated lists", () => {
    expect(covers("22,80,443", 80)).toBe(true);
    expect(covers("22,80,443", 81)).toBe(false);
  });

  it("handles ranges inclusively at both ends", () => {
    expect(covers("8000-8010", 8000)).toBe(true);
    expect(covers("8000-8010", 8010)).toBe(true);
    expect(covers("8000-8010", 7999)).toBe(false);
    expect(covers("8000-8010", 8011)).toBe(false);
  });

  it("handles a mix of singles and ranges", () => {
    expect(covers("22,8000-8010,443", 8005)).toBe(true);
    expect(covers("22,8000-8010,443", 443)).toBe(true);
    expect(covers("22,8000-8010,443", 9000)).toBe(false);
  });

  it("tolerates whitespace around parts", () => {
    expect(covers(" 22 , 80 - 90 ", 85)).toBe(true);
  });

  it("does not expand a full-range spec into a set", () => {
    const parsed = parsePortSpec("1-65535");
    expect(parsed).not.toBeNull();
    expect(parsed!.singles.size).toBe(0);
    expect(parsed!.ranges).toEqual([{ protocol: "tcp", lo: 1, hi: 65535 }]);
    expect(portSpecCovers(parsed!, 34567, "tcp")).toBe(true);
  });

  it("keeps the protocols apart", () => {
    // The bug this prevents: a TCP scan of port 53 concluding that UDP/53
    // just closed, or vice versa.
    expect(covers("53", 53, "tcp")).toBe(true);
    expect(covers("53", 53, "udp")).toBe(false);
    expect(covers("U:53", 53, "udp")).toBe(true);
    expect(covers("U:53", 53, "tcp")).toBe(false);
  });

  it("applies a protocol prefix only to its own comma-separated part", () => {
    // "U:53,80" is UDP/53 plus TCP/80 - masscan's and nmap's own reading.
    expect(covers("U:53,80", 53, "udp")).toBe(true);
    expect(covers("U:53,80", 80, "tcp")).toBe(true);
    expect(covers("U:53,80", 80, "udp")).toBe(false);
  });

  it("handles protocol-prefixed ranges and an explicit T:", () => {
    expect(covers("U:1000-1010", 1005, "udp")).toBe(true);
    expect(covers("U:1000-1010", 1005, "tcp")).toBe(false);
    expect(covers("T:8080", 8080, "tcp")).toBe(true);
  });

  it("treats an unknown protocol on an observation as tcp", () => {
    // Rows written before masscan's protocol was recorded carry "".
    expect(covers("443", 443, "")).toBe(true);
  });

  it("returns null rather than guessing on anything malformed", () => {
    // Each of these would be a wrong answer if it were coerced instead:
    // callers read null as "coverage unknown" and stay conservative.
    expect(parsePortSpec("")).toBeNull();
    expect(parsePortSpec("   ")).toBeNull();
    expect(parsePortSpec("http")).toBeNull();
    expect(parsePortSpec("S:53")).toBeNull();
    expect(parsePortSpec("0")).toBeNull();
    expect(parsePortSpec("70000")).toBeNull();
    expect(parsePortSpec("443-22")).toBeNull();
    expect(parsePortSpec("1-70000")).toBeNull();
    expect(parsePortSpec("80,")).not.toBeNull(); // trailing comma is harmless
  });
});
