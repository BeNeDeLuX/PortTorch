import { describe, expect, it } from "vitest";
import { MAX_TARGET_SPEC_LENGTH, isTargetEntry, parseTargetList } from "./targetList";

describe("isTargetEntry", () => {
  it("accepts every shape the Target field already takes", () => {
    for (const value of [
      "10.0.0.5",
      "192.168.1.0/24",
      "10.0.0.1-10.0.0.10",
      "2001:db8::1",
      "2001:db8::/32",
      "::1",
      "web1.internal",
      "host-01.corp.example.internal",
    ]) {
      expect(isTargetEntry(value), value).toBe(true);
    }
  });

  // The trap this exists for: a typo'd address made of digits and dots
  // would otherwise pass as a hostname, reach the scanner as a name,
  // fail to resolve and take the whole scan with it.
  it("rejects a malformed address rather than reading it as a hostname", () => {
    for (const value of ["192.168.0.999", "10.0.0", "10.0.0.5.6", "1.2.3.4/33", "010.0.0.5"]) {
      expect(isTargetEntry(value), value).toBe(false);
    }
  });

  // Deliberate and worth stating: a bare label is a valid hostname, but
  // in a file of addresses it is a header or prose far more often than a
  // short internal name - and the scanner fails a scan closed when a name
  // does not resolve, so accepting one costs the whole scan.
  it("rejects a bare single-label word, while keeping qualified names", () => {
    expect(isTargetEntry("fileserver")).toBe(false);
    expect(isTargetEntry("fileserver.corp.internal")).toBe(true);
  });

  it("rejects junk a spreadsheet export tends to carry", () => {
    for (const value of ["ip_address", '"10.0.0.5"', "10.0.0.5;", "-", "N/A"]) {
      expect(isTargetEntry(value), value).toBe(false);
    }
  });
});

describe("parseTargetList", () => {
  it("reads a comma-separated list into the spec the field takes", () => {
    const result = parseTargetList("10.0.0.1, 10.0.0.2, 10.0.0.3");
    expect(result.spec).toBe("10.0.0.1,10.0.0.2,10.0.0.3");
    expect(result.entries).toHaveLength(3);
    expect(result.errors).toEqual([]);
  });

  // One entry per line is the other shape a file of addresses actually
  // arrives in - it is what the scanner's own --targets-file takes.
  it("reads one entry per line, with # comments", () => {
    const result = parseTargetList("# gateways\n10.0.0.1\n10.0.0.2  # the spare\n\n10.0.0.3\n");
    expect(result.spec).toBe("10.0.0.1,10.0.0.2,10.0.0.3");
  });

  it("drops exact repeats and counts them", () => {
    const result = parseTargetList("10.0.0.1\n10.0.0.2\n10.0.0.1");
    expect(result.entries).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(result.duplicates).toBe(1);
  });

  // Two spellings of one IPv6 address are one address to scan.
  it("treats a repeat in different case as a duplicate, keeping the first spelling", () => {
    const result = parseTargetList("2001:DB8::1\n2001:db8::1");
    expect(result.entries).toEqual(["2001:DB8::1"]);
    expect(result.duplicates).toBe(1);
  });

  // An IPv6 address is full of colons, so a colon can never be a
  // separator - splitting on one would shred every v6 entry.
  it("keeps IPv6 addresses whole", () => {
    const result = parseTargetList("2001:db8::1\n2001:db8::2");
    expect(result.entries).toEqual(["2001:db8::1", "2001:db8::2"]);
    expect(result.errors).toEqual([]);
  });

  it("reports what it could not read, with the line it came from", () => {
    const result = parseTargetList("10.0.0.1\nnot an address\n10.0.0.2");
    expect(result.entries).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(result.errors).toEqual([
      { line: 2, value: "not" },
      { line: 2, value: "an" },
      { line: 2, value: "address" },
    ]);
  });

  it("returns an empty spec for an empty or comment-only file", () => {
    expect(parseTargetList("").spec).toBe("");
    expect(parseTargetList("# nothing here\n\n").spec).toBe("");
  });

  // The measured ceiling: the spec becomes one masscan argv entry, and
  // Linux caps one argument at 131072 bytes.
  it("keeps a realistic list well inside the spec limit", () => {
    const many = Array.from({ length: 4000 }, (_, i) => `10.${Math.floor(i / 256)}.${i % 256}.1`).join("\n");
    const result = parseTargetList(many);
    expect(result.entries).toHaveLength(4000);
    expect(result.spec.length).toBeLessThan(MAX_TARGET_SPEC_LENGTH);
  });
});
