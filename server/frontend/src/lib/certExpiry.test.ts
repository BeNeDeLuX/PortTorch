import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { certExpiryDaysLeft, certExpiryLabel, certExpiryStatus } from "./certExpiry";

// All three helpers compare against Date.now(), so the clock is pinned -
// otherwise a test asserting "29 days out is 'soon'" would be a slow
// time bomb that only fails when run near a boundary.
const NOW = new Date("2026-06-15T12:00:00.000Z");

function daysFromNow(days: number): string {
  return new Date(NOW.getTime() + days * 24 * 60 * 60 * 1000).toISOString();
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("certExpiryStatus", () => {
  it("reports a certificate already past its notAfter as expired", () => {
    expect(certExpiryStatus(daysFromNow(-1))).toBe("expired");
    expect(certExpiryStatus(daysFromNow(-365))).toBe("expired");
  });

  it("reports 'soon' strictly inside the 30-day window", () => {
    expect(certExpiryStatus(daysFromNow(29))).toBe("soon");
    expect(certExpiryStatus(daysFromNow(1))).toBe("soon");
  });

  it("treats exactly 30 days out as ok, not soon - the window is exclusive", () => {
    expect(certExpiryStatus(daysFromNow(30))).toBe("ok");
    expect(certExpiryStatus(daysFromNow(31))).toBe("ok");
  });

  it("returns 'unknown' for a null notAfter rather than guessing", () => {
    expect(certExpiryStatus(null)).toBe("unknown");
  });
});

describe("certExpiryDaysLeft", () => {
  it("floors toward the past, so a partially-elapsed day doesn't round up", () => {
    // 5 days and 23 hours out is still "5 days left", never 6.
    const almostSix = new Date(NOW.getTime() + 5 * 86_400_000 + 23 * 3_600_000).toISOString();
    expect(certExpiryDaysLeft(almostSix)).toBe(5);
  });

  it("goes negative once expired", () => {
    expect(certExpiryDaysLeft(daysFromNow(-3))).toBe(-3);
  });

  it("returns null when there's nothing to count down to", () => {
    expect(certExpiryDaysLeft(null)).toBeNull();
  });
});

describe("certExpiryLabel", () => {
  it("maps each status to its display string, with unknown rendering as empty", () => {
    expect(certExpiryLabel(daysFromNow(-1))).toBe("expired");
    expect(certExpiryLabel(daysFromNow(10))).toBe("expiring soon");
    expect(certExpiryLabel(daysFromNow(100))).toBe("valid");
    expect(certExpiryLabel(null)).toBe("");
  });
});
