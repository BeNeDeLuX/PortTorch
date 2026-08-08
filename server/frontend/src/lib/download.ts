// Client-side file download from in-memory content - used where the data
// to export is already loaded on screen (Host Detail's ports/host record),
// unlike the Dashboard's fleet-wide export which downloads directly from a
// backend URL since that data isn't otherwise fully fetched client-side.
export function downloadBlob(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Same quoting rule as the backend's export.csv (search/routes.ts's
// csvEscape) - only wrap in quotes when the value actually needs it.
export function csvEscape(value: string | number | null | undefined): string {
  const s = value == null ? "" : String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
