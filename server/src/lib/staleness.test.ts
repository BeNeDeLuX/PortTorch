import { describe, expect, it } from "vitest";
import { isStale, isStaleScanJob } from "./staleness";

const THRESHOLD = 60;

describe("isStale", () => {
  it("is not stale just now", () => {
    expect(isStale(new Date(), THRESHOLD)).toBe(false);
  });

  it("is not stale a few minutes ago", () => {
    expect(isStale(new Date(Date.now() - 10 * 60_000), THRESHOLD)).toBe(false);
  });

  it("is not stale exactly at the threshold boundary approached from below", () => {
    expect(isStale(new Date(Date.now() - 59 * 60_000), THRESHOLD)).toBe(false);
  });

  it("is stale well past the threshold", () => {
    expect(isStale(new Date(Date.now() - 120 * 60_000), THRESHOLD)).toBe(true);
  });

  it("accepts an ISO string as well as a Date", () => {
    expect(isStale(new Date(Date.now() - 120 * 60_000).toISOString(), THRESHOLD)).toBe(true);
  });

  it("respects a caller-supplied threshold different from the default", () => {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60_000);
    expect(isStale(tenMinutesAgo, 60)).toBe(false);
    expect(isStale(tenMinutesAgo, 5)).toBe(true);
  });
});

describe("isStaleScanJob", () => {
  const longAgo = new Date(Date.now() - 120 * 60_000);
  const justNow = new Date();

  it("falls back to startedAt when there's no progress row yet", () => {
    expect(isStaleScanJob(longAgo, null, THRESHOLD)).toBe(true);
    expect(isStaleScanJob(justNow, null, THRESHOLD)).toBe(false);
  });

  it("is NOT stale when startedAt is old but a recent progress heartbeat exists - the exact case a long masscan-only pass must not be flagged", () => {
    expect(isStaleScanJob(longAgo, justNow, THRESHOLD)).toBe(false);
  });

  it("is stale when both startedAt and the last progress heartbeat are old - the scanner process actually died", () => {
    expect(isStaleScanJob(longAgo, longAgo, THRESHOLD)).toBe(true);
  });
});
