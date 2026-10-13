import { describe, expect, it } from "vitest";
import { minorReleasesBehind } from "./semver";

describe("minorReleasesBehind", () => {
  it("counts minor releases, not patches", () => {
    expect(minorReleasesBehind("0.23.0", "0.30.2")).toBe(7);
    expect(minorReleasesBehind("0.30.0", "0.30.2")).toBe(0);
    expect(minorReleasesBehind("0.30.2", "0.30.2")).toBeNull();
  });
  it("treats a different major as far behind", () => {
    expect(minorReleasesBehind("0.30.0", "1.0.0")).toBe(Number.POSITIVE_INFINITY);
  });
  it("is null when a version is unknown", () => {
    expect(minorReleasesBehind(null, "0.30.0")).toBeNull();
  });
});
