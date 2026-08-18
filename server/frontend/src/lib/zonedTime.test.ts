import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  resolveTimezone,
  shiftWeekday,
  utcHourMinuteToZonedTime,
  utcIsoToZonedDateTimeLocal,
  zonedDateTimeToUtcIso,
  zonedTimeToUtcHourMinute,
} from "./zonedTime";

// This module exists because of a real reported bug: the schedule pickers
// used to prepend "Z" to whatever the browser's native time input gave
// back, treating a wall-clock pick as if it were already UTC. Europe/Berlin
// is used throughout because its two offsets (+01:00 winter, +02:00 summer)
// make an off-by-one-hour or missing-DST mistake visible, unlike UTC.

describe("zonedDateTimeToUtcIso", () => {
  it("applies the zone's winter (standard) offset", () => {
    // 2026-01-15 09:00 Berlin (CET, UTC+1) -> 08:00 UTC
    expect(zonedDateTimeToUtcIso("2026-01-15", "09:00", "Europe/Berlin")).toBe("2026-01-15T08:00:00.000Z");
  });

  it("applies the zone's summer (DST) offset for the same wall-clock time", () => {
    // 2026-07-15 09:00 Berlin (CEST, UTC+2) -> 07:00 UTC. Same input time
    // as above, one hour earlier in UTC - the whole point of doing this
    // per-date rather than with a fixed offset.
    expect(zonedDateTimeToUtcIso("2026-07-15", "09:00", "Europe/Berlin")).toBe("2026-07-15T07:00:00.000Z");
  });

  it("rolls the date backward when the pick is early enough to cross midnight in UTC", () => {
    // 2026-01-15 00:30 Berlin -> 2026-01-14 23:30 UTC (previous day).
    expect(zonedDateTimeToUtcIso("2026-01-15", "00:30", "Europe/Berlin")).toBe("2026-01-14T23:30:00.000Z");
  });

  it("is an identity conversion for UTC itself", () => {
    expect(zonedDateTimeToUtcIso("2026-03-01", "14:45", "UTC")).toBe("2026-03-01T14:45:00.000Z");
  });

  it("handles a zone west of UTC, where the UTC instant is later", () => {
    // 2026-01-15 20:00 New York (EST, UTC-5) -> 2026-01-16 01:00 UTC.
    expect(zonedDateTimeToUtcIso("2026-01-15", "20:00", "America/New_York")).toBe("2026-01-16T01:00:00.000Z");
  });
});

describe("utcIsoToZonedDateTimeLocal", () => {
  it("renders a real UTC instant as datetime-local-shaped wall clock in the zone", () => {
    expect(utcIsoToZonedDateTimeLocal("2026-01-15T08:00:00.000Z", "Europe/Berlin")).toBe("2026-01-15T09:00");
    expect(utcIsoToZonedDateTimeLocal("2026-07-15T07:00:00.000Z", "Europe/Berlin")).toBe("2026-07-15T09:00");
  });

  it("round-trips losslessly with zonedDateTimeToUtcIso, in both DST states", () => {
    for (const [date, time] of [
      ["2026-01-15", "09:00"],
      ["2026-07-15", "09:00"],
      ["2026-01-15", "00:30"],
      ["2026-12-31", "23:59"],
    ]) {
      const utc = zonedDateTimeToUtcIso(date, time, "Europe/Berlin");
      expect(utcIsoToZonedDateTimeLocal(utc, "Europe/Berlin")).toBe(`${date}T${time}`);
    }
  });

  it("renders midnight as 00:00, not 24:00 - Intl reports hour 24 with hour12:false", () => {
    expect(utcIsoToZonedDateTimeLocal("2026-01-14T23:00:00.000Z", "Europe/Berlin")).toBe("2026-01-15T00:00");
  });
});

describe("zonedTimeToUtcHourMinute", () => {
  // Pinned to a winter date so Berlin is at its +01:00 standard offset -
  // this function deliberately resolves the zone's *current* offset (see
  // its doc comment on why a plain cron expression can't be perpetually
  // DST-correct), so the result depends on "today".
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("converts a wall-clock time to its UTC equivalent with no day shift", () => {
    expect(zonedTimeToUtcHourMinute("09:00", "Europe/Berlin")).toEqual({ hour: 8, minute: 0, dayShift: 0 });
  });

  it("reports dayShift -1 when the UTC equivalent falls on the previous day", () => {
    // The exact case the module's own doc comment calls out: "Monday 00:30
    // Berlin" in winter is "Sunday 23:30 UTC", so a weekday selection has
    // to shift back a day or the schedule fires on the wrong day.
    expect(zonedTimeToUtcHourMinute("00:30", "Europe/Berlin")).toEqual({ hour: 23, minute: 30, dayShift: -1 });
  });

  it("reports dayShift +1 when the UTC equivalent falls on the next day", () => {
    // 20:00 New York (UTC-5) is 01:00 UTC the following day.
    expect(zonedTimeToUtcHourMinute("20:00", "America/New_York")).toEqual({ hour: 1, minute: 0, dayShift: 1 });
  });

  it("is a no-op for UTC", () => {
    expect(zonedTimeToUtcHourMinute("09:00", "UTC")).toEqual({ hour: 9, minute: 0, dayShift: 0 });
  });

  // Regression: <input type="time"> can be cleared, and Schedules.tsx
  // feeds its value straight into this during render (useMemo). The
  // original NaN-only guard missed "" (which splits to one element, so
  // the minute is `undefined`, and Number.isNaN(undefined) is false),
  // producing an invalid Date and throwing RangeError out of the render.
  it("falls back to 09:00 for an empty or unparseable time instead of throwing", () => {
    expect(zonedTimeToUtcHourMinute("", "UTC")).toEqual({ hour: 9, minute: 0, dayShift: 0 });
    expect(zonedTimeToUtcHourMinute("abc", "UTC")).toEqual({ hour: 9, minute: 0, dayShift: 0 });
    expect(zonedTimeToUtcHourMinute("09", "UTC")).toEqual({ hour: 9, minute: 0, dayShift: 0 });
    expect(zonedTimeToUtcHourMinute("ab:cd", "UTC")).toEqual({ hour: 9, minute: 0, dayShift: 0 });
  });

  it("still reads a legitimate midnight pick as 00:00, not as the 09:00 fallback", () => {
    expect(zonedTimeToUtcHourMinute("00:00", "UTC")).toEqual({ hour: 0, minute: 0, dayShift: 0 });
  });
});

describe("utcHourMinuteToZonedTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("inverts zonedTimeToUtcHourMinute, including the day shift", () => {
    // Forward: 00:30 Berlin -> 23:30 UTC, dayShift -1.
    // Back: 23:30 UTC -> 00:30 Berlin, dayShift +1 (the mirror image, so
    // Schedules.tsx can reverse it with shiftWeekday(day, -dayShift)).
    expect(utcHourMinuteToZonedTime(23, 30, "Europe/Berlin")).toEqual({ time: "00:30", dayShift: 1 });
  });

  it("round-trips a range of times back to what was originally picked", () => {
    for (const time of ["00:30", "09:00", "13:45", "23:59"]) {
      const { hour, minute } = zonedTimeToUtcHourMinute(time, "Europe/Berlin");
      expect(utcHourMinuteToZonedTime(hour, minute, "Europe/Berlin").time).toBe(time);
    }
  });

  it("renders local midnight as 00:00, not 24:00", () => {
    expect(utcHourMinuteToZonedTime(23, 0, "Europe/Berlin").time).toBe("00:00");
  });
});

describe("shiftWeekday", () => {
  it("wraps around both ends of the Sun-Sat range", () => {
    expect(shiftWeekday(1, -1)).toBe(0); // Monday back to Sunday
    expect(shiftWeekday(0, -1)).toBe(6); // Sunday back to Saturday
    expect(shiftWeekday(6, 1)).toBe(0); // Saturday forward to Sunday
    expect(shiftWeekday(3, 0)).toBe(3); // no shift
  });
});

describe("resolveTimezone", () => {
  it("returns an explicit preference unchanged", () => {
    expect(resolveTimezone("Europe/Berlin")).toBe("Europe/Berlin");
  });

  it("falls back to the runtime's own zone when no preference is set", () => {
    expect(resolveTimezone(null)).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);
  });
});
