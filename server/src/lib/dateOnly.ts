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
