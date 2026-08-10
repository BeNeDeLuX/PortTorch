// Shared by search/routes.ts's lastSeenAfter/lastSeenBefore host filters
// and audit/routes.ts's from/until audit log filter - both take a plain
// "YYYY-MM-DD" string (an HTML date input's value) and need the same
// UTC-midnight parsing so the two features agree on what a given day
// means.
export function parseDateOnly(value: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const d = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

// The inverse direction: node-postgres returns a Postgres `date` column as
// a JS Date (midnight UTC), not the plain "YYYY-MM-DD" string it was
// written as - a real, confirmed bug once (digest/emailDigest.ts's
// "already sent today" guard silently never matched when compared against
// a Date via `===`, re-sending on every hourly tick). Originally a private
// copy inside emailDigest.ts; pulled out here once kev_cache.date_added
// (search/routes.ts) needed the exact same normalization, rather than a
// third hand-rolled copy of bug-prone Date-handling logic.
export function toDateOnlyString(value: Date | string | null): string | null {
  if (value === null) return null;
  return (value instanceof Date ? value : new Date(value)).toISOString().slice(0, 10);
}
