// Shared by the server-side export.csv endpoints (hosts, audit log).
// Was copy-pasted identically in both route files; one copy instead.
//
// Note the frontend has its own separate copy in frontend/src/lib/download.ts
// for the client-side exports (Vulnerabilities/Web Findings/Certificates,
// via TableExport.tsx) - deliberately not shared across that boundary,
// same reasoning as the three independent compareSemver copies.
//
// Quotes only when the value actually needs it, per RFC 4180 - a bare
// value containing none of `"`, `,`, CR or LF is emitted as-is, which is
// what keeps these files diffable and readable in a plain editor.
export function csvEscape(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "";
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
