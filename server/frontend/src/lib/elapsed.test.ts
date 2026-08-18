import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { durationLabel, elapsedLabel } from "./elapsed";

describe("durationLabel", () => {
  it("shows bare seconds below a minute", () => {
    expect(durationLabel(0)).toBe("0s");
    expect(durationLabel(59_999)).toBe("59s");
  });

  it("switches to Xm Ys at exactly one minute", () => {
    expect(durationLabel(60_000)).toBe("1m 0s");
    expect(durationLabel(90_000)).toBe("1m 30s");
    expect(durationLabel(59 * 60_000 + 59_000)).toBe("59m 59s");
  });

  it("switches to Xh Ym at exactly one hour, dropping seconds", () => {
    expect(durationLabel(3_600_000)).toBe("1h 0m");
    expect(durationLabel(3_600_000 + 30 * 60_000)).toBe("1h 30m");
    expect(durationLabel(25 * 3_600_000)).toBe("25h 0m");
  });

  it("clamps a negative duration to zero rather than rendering '-1s'", () => {
    expect(durationLabel(-5000)).toBe("0s");
  });

  it("truncates sub-second remainders instead of rounding up", () => {
    expect(durationLabel(1999)).toBe("1s");
  });
});

describe("elapsedLabel", () => {
  const NOW = new Date("2026-06-15T12:00:00.000Z");

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("formats how long ago startedAt was, in durationLabel's shape", () => {
    expect(elapsedLabel(new Date(NOW.getTime() - 45_000).toISOString())).toBe("45s");
    expect(elapsedLabel(new Date(NOW.getTime() - 5 * 60_000).toISOString())).toBe("5m 0s");
  });

  it("clamps a future startedAt to 0s - a scanner whose clock runs ahead must not show a negative runtime", () => {
    expect(elapsedLabel(new Date(NOW.getTime() + 60_000).toISOString())).toBe("0s");
  });
});
