// "Only run this schedule between 22:00 and 06:00, weekdays only."
//
// Stored on scan_schedules as minutes-since-midnight rather than a
// Postgres `time` column: the only operation ever performed is a range
// comparison, and integers make the midnight wrap-around (start > end)
// explicit instead of hiding it behind time arithmetic. It also sidesteps
// node-postgres returning a `time` column as a string in a format that
// varies with the server's DateStyle.

export interface ScanWindow {
  // Both null, or both set. Minutes since local midnight, 0-1439.
  startMinute: number | null;
  endMinute: number | null;
  // JS getDay() numbering: 0 = Sunday .. 6 = Saturday. Null or empty
  // means every day.
  days: number[] | null;
  // IANA zone the window is expressed in. Null means UTC, matching how
  // cron expressions are already evaluated (see lib/cron.ts).
  timezone: string | null;
}

export const MINUTES_PER_DAY = 1440;

// Local wall-clock minute-of-day and weekday in a given IANA zone,
// without pulling in a date library: Intl already knows every zone's
// offset and DST rules, and formatToParts is the supported way to read
// the individual fields back out.
export function zonedMinuteAndDay(now: Date, timezone: string | null): { minute: number; day: number } {
  const tz = timezone ?? "UTC";
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hour: "2-digit",
    minute: "2-digit",
    weekday: "short",
    hour12: false,
  }).formatToParts(now);

  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  // hour12:false still yields "24" for midnight in some ICU versions -
  // normalising it here rather than trusting one implementation.
  const hour = Number(get("hour")) % 24;
  const minute = Number(get("minute"));
  const weekdays: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return { minute: hour * 60 + minute, day: weekdays[get("weekday")] ?? 0 };
}

// A window with no start/end allows everything - that's the state every
// schedule created before this feature existed is in, so "no window
// configured" has to mean "unrestricted", never "never runs".
export function isWithinScanWindow(now: Date, window: ScanWindow): boolean {
  const { startMinute, endMinute, days } = window;
  const hasDays = days !== null && days.length > 0;
  if (startMinute === null || endMinute === null) {
    if (!hasDays) return true;
    return days.includes(zonedMinuteAndDay(now, window.timezone).day);
  }

  const { minute, day } = zonedMinuteAndDay(now, window.timezone);

  if (startMinute === endMinute) {
    // A zero-width window would otherwise mean "never", which is never
    // what anyone intends by typing the same time twice - read as "all
    // day", leaving the day-of-week filter as the only restriction.
    return !hasDays || days.includes(day);
  }

  const inTimeRange =
    startMinute < endMinute
      ? minute >= startMinute && minute < endMinute
      : // Wraps past midnight (e.g. 22:00-06:00): either side counts.
        minute >= startMinute || minute < endMinute;

  if (!inTimeRange) return false;
  if (!hasDays) return true;

  // For a wrapping window, the day-of-week test applies to the day the
  // window *started* on, not the calendar day the clock happens to be in.
  // Otherwise "weekdays, 22:00-06:00" would cut itself off at midnight on
  // Friday night and, worse, silently allow the early hours of Saturday
  // through as if Friday's window had never ended.
  const effectiveDay = startMinute > endMinute && minute < endMinute ? (day + 6) % 7 : day;
  return days.includes(effectiveDay);
}
