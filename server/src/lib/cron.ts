import { CronExpressionParser } from "cron-parser";

// Schedules are stored/evaluated in UTC - the dashboard already renders
// every other timestamp (next_run_at, last_run_at, etc.) via the browser's
// local timezone, so a UTC-authored cron expression is consistent with how
// scan_schedules already works for the plain interval type (which has no
// timezone concept at all).
const CRON_OPTIONS = { tz: "UTC" } as const;

export function isValidCronExpression(expr: string): boolean {
  try {
    CronExpressionParser.parse(expr, CRON_OPTIONS);
    return true;
  } catch {
    return false;
  }
}

export function nextCronRun(expr: string, from: Date = new Date()): Date {
  const interval = CronExpressionParser.parse(expr, { ...CRON_OPTIONS, currentDate: from });
  return interval.next().toDate();
}
