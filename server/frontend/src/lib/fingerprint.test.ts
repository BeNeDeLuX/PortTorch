import { describe, expect, it } from "vitest";
import { fingerprintQuery } from "./fingerprint";

describe("fingerprintQuery", () => {
  it("accepts the shapes a fingerprint is pasted in", () => {
    expect(fingerprintQuery("BB:A4:D2:B3:AF:F3:3F:E9")).toBe("bba4d2b3aff33fe9");
    expect(fingerprintQuery("bb a4 d2 b3 af f3")).toBe("bba4d2b3aff3");
    expect(fingerprintQuery("  bba4d2b3aff33fe98b2d69dcd048eedd  ")).toBe("bba4d2b3aff33fe98b2d69dcd048eedd");
  });
  it("leaves short or non-hex text to the other fields", () => {
    expect(fingerprintQuery("443")).toBeNull();
    expect(fingerprintQuery("bba4d2")).toBeNull();
    expect(fingerprintQuery("example.org")).toBeNull();
    expect(fingerprintQuery("10.0.0.15")).toBeNull();
  });
});
