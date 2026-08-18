// Converts a wall-clock date/time, as picked in a specific IANA timezone,
// into its correct UTC equivalent - needed because the browser's native
// <input type="datetime-local">/<input type="time"> have no concept of an
// arbitrary named timezone (only the browser's own local one), so a value
// typed there has to be reinterpreted against the user's *preferred*
// timezone (Account settings) before it can be sent to the backend, which
// stores/evaluates everything in UTC.
//
// There's no first-class "parse wall-clock time in zone X" API in
// JS/browsers without a library, so this uses the standard round-trip
// technique: interpret the wall-clock components as if they were UTC (a
// "naive" instant), ask Intl.DateTimeFormat how that instant's wall-clock
// reads in the target zone, and the difference between the two is the
// zone's UTC offset at that moment - accurate for the vast majority of
// real-world picks, with an acceptable, extremely rare edge case right at
// a DST-transition's skipped/ambiguous hour.

export function resolveTimezone(pref: string | null): string {
  return pref ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
}

function offsetMsAt(naiveUtcMillis: number, timeZone: string): number {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const parts = dtf.formatToParts(new Date(naiveUtcMillis));
  const map: Record<string, string> = {};
  for (const p of parts) {
    if (p.type !== "literal") map[p.type] = p.value;
  }
  const readBackAsUtc = Date.UTC(
    Number(map.year),
    Number(map.month) - 1,
    Number(map.day),
    Number(map.hour) % 24, // Intl reports midnight as "24" with hour12: false
    Number(map.minute),
    Number(map.second)
  );
  return readBackAsUtc - naiveUtcMillis;
}

// For the "once" schedule type: a full date ("YYYY-MM-DD") + time
// ("HH:MM") pick, both wall-clock in timeZone, converted to a UTC ISO
// string. This is fully correct with no caveats - a one-time event has no
// DST-recurrence problem, unlike the daily/weekly builder below.
export function zonedDateTimeToUtcIso(dateStr: string, timeStr: string, timeZone: string): string {
  const [year, month, day] = dateStr.split("-").map(Number);
  const [hour, minute] = timeStr.split(":").map(Number);
  const naiveUtc = Date.UTC(year, month - 1, day, hour, minute, 0);
  return new Date(naiveUtc - offsetMsAt(naiveUtc, timeZone)).toISOString();
}

// For the recurring cron builder's daily "Time" field: converts a
// "HH:MM" wall-clock time (interpreted in timeZone, using *today's* date
// only to resolve the zone's *current* UTC offset) into its UTC
// hour/minute, plus how many calendar days the date shifts by (-1, 0, or
// +1) - needed so a "days of week"/"monthly weekday" pick can be shifted
// to the matching UTC weekday (e.g. "Monday 00:30 Berlin" in winter is
// "Sunday 23:30 UTC" - the cron's day-of-week field has to say Sunday).
// Deliberately NOT perpetually DST-correct: a plain cron expression has
// no timezone concept of its own, so this bakes in *today's* offset -
// the schedule keeps running at that fixed UTC time even after the next
// DST transition, same as manually writing a UTC cron expression would.
export function zonedTimeToUtcHourMinute(timeStr: string, timeZone: string): { hour: number; minute: number; dayShift: number } {
  // <input type="time"> can be cleared, handing back "" - which splits to
  // a single element, so rawMinute is `undefined`, not NaN. Number.isNaN
  // is false for undefined, so an isNaN-only guard let it through and
  // Date.UTC below produced NaN, throwing "Invalid time value" out of
  // Intl.formatToParts - during render, since Schedules.tsx computes the
  // generated cron in a useMemo. Requiring both parts to be present and
  // finite covers the empty, partial, and non-numeric cases alike.
  const parts = timeStr.split(":");
  const rawHour = Number(parts[0]);
  const rawMinute = Number(parts[1]);
  const hour = parts.length === 2 && Number.isFinite(rawHour) ? rawHour : 9;
  const minute = parts.length === 2 && Number.isFinite(rawMinute) ? rawMinute : 0;
  const now = new Date();
  const naiveUtc = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hour, minute, 0);
  const utcInstant = naiveUtc - offsetMsAt(naiveUtc, timeZone);
  const utcDate = new Date(utcInstant);
  const naiveDay = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const utcDay = Date.UTC(utcDate.getUTCFullYear(), utcDate.getUTCMonth(), utcDate.getUTCDate());
  return {
    hour: utcDate.getUTCHours(),
    minute: utcDate.getUTCMinutes(),
    dayShift: Math.round((utcDay - naiveDay) / 86_400_000),
  };
}

// Shifts a 0-6 (Sun-Sat) weekday index by dayShift, wrapping around.
export function shiftWeekday(day: number, dayShift: number): number {
  return (day + dayShift + 7) % 7;
}

// Inverse of zonedDateTimeToUtcIso - for pre-filling the "once" edit form:
// formats a real, already-known UTC instant as a datetime-local-shaped
// "YYYY-MM-DDTHH:MM" string in timeZone. Simpler than the forward
// direction's round-trip trick: since isoString is a real instant (not an
// ambiguous wall-clock string), Intl.DateTimeFormat can read its local
// wall-clock in timeZone directly, no offset arithmetic needed.
export function utcIsoToZonedDateTimeLocal(isoString: string, timeZone: string): string {
  const dtf = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  const parts = dtf.formatToParts(new Date(isoString));
  const map: Record<string, string> = {};
  for (const p of parts) {
    if (p.type !== "literal") map[p.type] = p.value;
  }
  const hour = map.hour === "24" ? "00" : map.hour;
  return `${map.year}-${map.month}-${map.day}T${hour}:${map.minute}`;
}

// Inverse of zonedTimeToUtcHourMinute - for pre-filling the recurring cron
// builder's edit form: converts a stored UTC hour/minute (using *today's*
// date to resolve the zone's *current* offset, same scoping as the
// forward direction) back to local "HH:MM" plus the same ±1-day
// dayShift, so a "days"/"monthly weekday" selection can be reverse-shifted
// (shiftWeekday(day, -dayShift)) to match what the user originally picked.
export function utcHourMinuteToZonedTime(hour: number, minute: number, timeZone: string): { time: string; dayShift: number } {
  const now = new Date();
  const utcInstant = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hour, minute, 0);
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  const parts = dtf.formatToParts(new Date(utcInstant));
  const map: Record<string, string> = {};
  for (const p of parts) {
    if (p.type !== "literal") map[p.type] = p.value;
  }
  const localHour = map.hour === "24" ? 0 : Number(map.hour);
  const localDay = Date.UTC(Number(map.year), Number(map.month) - 1, Number(map.day));
  const utcDay = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return {
    time: `${String(localHour).padStart(2, "0")}:${map.minute}`,
    dayShift: Math.round((localDay - utcDay) / 86_400_000),
  };
}
