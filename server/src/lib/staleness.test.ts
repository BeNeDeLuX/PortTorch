import { describe, expect, it } from "vitest";
import { isStale } from "./staleness";

// Uses the default threshold (STALE_SCAN_THRESHOLD_MINUTES unset -> 60min,
// see config.ts) - vitest.config.ts's test env intentionally doesn't set
// this var, so these assertions stay valid as long as the default itself
// doesn't change without the test being updated alongside it.
describe("isStale", () => {
  it("is not stale just now", () => {
    expect(isStale(new Date())).toBe(false);
  });

  it("is not stale a few minutes ago", () => {
    expect(isStale(new Date(Date.now() - 10 * 60_000))).toBe(false);
  });

  it("is not stale exactly at the threshold boundary approached from below", () => {
    expect(isStale(new Date(Date.now() - 59 * 60_000))).toBe(false);
  });

  it("is stale well past the threshold", () => {
    expect(isStale(new Date(Date.now() - 120 * 60_000))).toBe(true);
  });

  it("accepts an ISO string as well as a Date", () => {
    expect(isStale(new Date(Date.now() - 120 * 60_000).toISOString())).toBe(true);
  });
});
