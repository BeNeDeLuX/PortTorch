import { describe, expect, it } from "vitest";
import { isWithinScanWindow, zonedMinuteAndDay, type ScanWindow } from "./scanWindow";

const NO_WINDOW: ScanWindow = { startMinute: null, endMinute: null, days: null, timezone: null };

// 2026-08-28 is a Friday.
const friday = (hhmm: string, tz = "Z") => new Date(`2026-08-28T${hhmm}:00${tz}`);
const saturday = (hhmm: string, tz = "Z") => new Date(`2026-08-29T${hhmm}:00${tz}`);
const sunday = (hhmm: string, tz = "Z") => new Date(`2026-08-30T${hhmm}:00${tz}`);

function win(p: Partial<ScanWindow>): ScanWindow {
  return { ...NO_WINDOW, ...p };
}

describe("isWithinScanWindow", () => {
  it("allows everything when nothing is configured", () => {
    // Every schedule that existed before windows did is in this state.
    expect(isWithinScanWindow(friday("13:00"), NO_WINDOW)).toBe(true);
    expect(isWithinScanWindow(friday("03:00"), NO_WINDOW)).toBe(true);
  });

  it("handles a normal same-day window", () => {
    const w = win({ startMinute: 9 * 60, endMinute: 17 * 60 });
    expect(isWithinScanWindow(friday("08:59"), w)).toBe(false);
    expect(isWithinScanWindow(friday("09:00"), w)).toBe(true);
    expect(isWithinScanWindow(friday("16:59"), w)).toBe(true);
    // End is exclusive, so a 09:00-17:00 window doesn't start a scan at
    // exactly 17:00.
    expect(isWithinScanWindow(friday("17:00"), w)).toBe(false);
  });

  it("handles a window that wraps past midnight", () => {
    const w = win({ startMinute: 22 * 60, endMinute: 6 * 60 });
    expect(isWithinScanWindow(friday("21:59"), w)).toBe(false);
    expect(isWithinScanWindow(friday("22:00"), w)).toBe(true);
    expect(isWithinScanWindow(friday("23:59"), w)).toBe(true);
    expect(isWithinScanWindow(saturday("00:00"), w)).toBe(true);
    expect(isWithinScanWindow(saturday("05:59"), w)).toBe(true);
    expect(isWithinScanWindow(saturday("06:00"), w)).toBe(false);
    expect(isWithinScanWindow(saturday("12:00"), w)).toBe(false);
  });

  it("reads an identical start and end as all day, not as never", () => {
    const w = win({ startMinute: 60, endMinute: 60 });
    expect(isWithinScanWindow(friday("00:30"), w)).toBe(true);
    expect(isWithinScanWindow(friday("13:00"), w)).toBe(true);
  });

  it("restricts by weekday", () => {
    const weekdaysOnly = win({ days: [1, 2, 3, 4, 5] });
    expect(isWithinScanWindow(friday("13:00"), weekdaysOnly)).toBe(true);
    expect(isWithinScanWindow(saturday("13:00"), weekdaysOnly)).toBe(false);
    expect(isWithinScanWindow(sunday("13:00"), weekdaysOnly)).toBe(false);
  });

  it("treats an empty day list as every day, like a null one", () => {
    expect(isWithinScanWindow(saturday("13:00"), win({ days: [] }))).toBe(true);
  });

  it("attributes a wrapping window's small hours to the day it started on", () => {
    // "Weekday nights, 22:00-06:00" must run Friday 22:00 through
    // Saturday 06:00 as one block, and must NOT start again on Saturday
    // evening. Naively testing the calendar day would get both wrong.
    const w = win({ startMinute: 22 * 60, endMinute: 6 * 60, days: [1, 2, 3, 4, 5] });
    expect(isWithinScanWindow(friday("23:00"), w)).toBe(true);
    expect(isWithinScanWindow(saturday("02:00"), w)).toBe(true); // still Friday's window
    expect(isWithinScanWindow(saturday("23:00"), w)).toBe(false); // Saturday isn't allowed
    expect(isWithinScanWindow(sunday("02:00"), w)).toBe(false); // ...so neither is its tail
  });

  it("evaluates the window in its own timezone, not the server's", () => {
    const w = win({ startMinute: 22 * 60, endMinute: 23 * 60, timezone: "Europe/Berlin" });
    // 20:30 UTC is 22:30 in Berlin (CEST, UTC+2) - inside the window.
    expect(isWithinScanWindow(friday("20:30"), w)).toBe(true);
    // 22:30 UTC is 00:30 the next day in Berlin - outside it.
    expect(isWithinScanWindow(friday("22:30"), w)).toBe(false);
  });

  it("gets the weekday right across a timezone's date boundary", () => {
    // 23:30 UTC on Friday is already Saturday 01:30 in Berlin, so a
    // weekdays-only window must reject it.
    const w = win({ days: [1, 2, 3, 4, 5], timezone: "Europe/Berlin" });
    expect(isWithinScanWindow(friday("23:30"), w)).toBe(false);
    expect(isWithinScanWindow(friday("12:00"), w)).toBe(true);
  });

  it("defaults a null timezone to UTC", () => {
    expect(zonedMinuteAndDay(friday("13:37"), null)).toEqual({ minute: 13 * 60 + 37, day: 5 });
  });

  it("reports midnight as minute 0, not 1440", () => {
    // hour12:false yields "24" rather than "00" in some ICU builds, which
    // would put midnight outside every window that ends before 24:00.
    expect(zonedMinuteAndDay(saturday("00:00"), null).minute).toBe(0);
    expect(zonedMinuteAndDay(saturday("00:30"), null).minute).toBe(30);
  });
});
