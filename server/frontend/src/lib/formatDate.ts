import type { UserPreferences } from "../api";

export type DatePrefs = Pick<UserPreferences, "timezone" | "timeFormat">;

// `timeZone: undefined` and `hour12: undefined` both mean "let Intl pick" -
// the browser's own local zone, and the current locale's usual hour cycle
// (e.g. en-US defaults to 12h, de-DE to 24h) - which is exactly what "no
// preference set" (null) should fall back to.
function hour12Option(timeFormat: DatePrefs["timeFormat"]): boolean | undefined {
  if (timeFormat === "h12") return true;
  if (timeFormat === "h24") return false;
  return undefined;
}

export function formatDateTime(value: string | Date, prefs: DatePrefs): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: prefs.timezone ?? undefined,
    hour12: hour12Option(prefs.timeFormat),
  }).format(date);
}

export function formatDateOnly(value: string | Date, prefs: DatePrefs): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeZone: prefs.timezone ?? undefined,
  }).format(date);
}
