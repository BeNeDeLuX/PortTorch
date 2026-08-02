import { describe, expect, it } from "vitest";
import { isValidCronExpression, nextCronRun } from "./cron";

describe("isValidCronExpression", () => {
  it("accepts a plain 5-field expression", () => {
    expect(isValidCronExpression("0 9 * * *")).toBe(true);
  });

  it("accepts the Quartz-style nth-weekday-of-month extension", () => {
    expect(isValidCronExpression("0 9 * * 0#1")).toBe(true);
    expect(isValidCronExpression("0 9 * * 0L")).toBe(true);
  });

  it("rejects a malformed expression", () => {
    expect(isValidCronExpression("not a cron expression")).toBe(false);
  });

  it("rejects a field out of range", () => {
    expect(isValidCronExpression("0 25 * * *")).toBe(false);
  });
});

describe("nextCronRun", () => {
  const from = new Date("2024-01-01T00:00:00.000Z");

  it("computes the next daily run in UTC", () => {
    const next = nextCronRun("0 9 * * *", from);
    expect(next.toISOString()).toBe("2024-01-01T09:00:00.000Z");
  });

  // POSIX cron ORs the day-of-month and day-of-week fields when both are
  // restricted, rather than ANDing them - a plain "1-7 * 0" would match
  // every day 1-7 of the month AND every Sunday, not just the first
  // Sunday. Confirmed (both here and manually against cron-parser
  // directly, cross-checked against real calendar dates via `date -d`)
  // that the Quartz "#" extension is genuinely necessary for this.
  it("computes the first Sunday of the month at 09:00 UTC", () => {
    // 2024-01-07 is a real, calendar-verified Sunday.
    const next = nextCronRun("0 9 * * 0#1", from);
    expect(next.toISOString()).toBe("2024-01-07T09:00:00.000Z");
  });

  it("computes the last Sunday of the month at 09:00 UTC", () => {
    // 2024-01-28 is a real, calendar-verified (and final) Sunday in
    // January 2024.
    const next = nextCronRun("0 9 * * 0L", from);
    expect(next.toISOString()).toBe("2024-01-28T09:00:00.000Z");
  });

  it("treats the expression as UTC regardless of the host timezone", () => {
    // A from-date already past 09:00 UTC on the 1st should roll to the
    // 2nd, not re-fire the same day - this would only be wrong if the
    // expression were evaluated in a non-UTC zone.
    const later = new Date("2024-01-01T10:00:00.000Z");
    const next = nextCronRun("0 9 * * *", later);
    expect(next.toISOString()).toBe("2024-01-02T09:00:00.000Z");
  });
});
