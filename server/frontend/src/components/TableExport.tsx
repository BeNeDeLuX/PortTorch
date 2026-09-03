import { IconDownload, IconPrinter } from "./icons";
import { csvEscape, downloadBlob } from "../lib/download";

export interface ExportColumn<T> {
  header: string;
  value: (row: T) => string | number | null | undefined;
}

// Export control for the flat fleet-wide tables (Vulnerabilities, Web
// Findings, Certificates) - the three pages that had no export at all
// while Dashboard/Digest/Audit did, which is exactly backwards: these are
// the lists you hand to an auditor, a ticket, or a customer.
//
// Three plain buttons rather than the modal Host Detail/Digest use:
// those offer a scoping choice (this host vs. filters), which doesn't
// apply to a flat table. Here the scope is simply "what's on screen right
// now", so a modal would just add a click.
//
// PDF is window.print() against the page's own DOM, exactly as Host
// Detail's is - no library, no server round trip, and whatever is
// rendered (including the current filter and sort) is what comes out.
// styles.css's @media print block already hides the nav, search bar and
// list controls, so what prints is the heading plus the table.
//
// Exports the already-filtered, already-sorted rows the caller passes in,
// never a re-fetch - same discipline as DigestExportModal, so an export
// can't silently disagree with the table above it.
export default function TableExport<T>({
  rows,
  columns,
  filenameBase,
  jsonRows,
}: {
  rows: T[];
  columns: ExportColumn<T>[];
  filenameBase: string;
  // Optional projection for the JSON export - defaults to the raw rows,
  // which is usually what an external consumer wants (every field, not
  // just the visible columns).
  jsonRows?: (rows: T[]) => unknown;
}) {
  const stamp = new Date().toISOString().slice(0, 10);

  function exportPdf() {
    window.print();
  }

  function exportCsv() {
    const lines = [columns.map((c) => csvEscape(c.header)).join(",")];
    for (const row of rows) {
      lines.push(columns.map((c) => csvEscape(c.value(row))).join(","));
    }
    downloadBlob(`${filenameBase}-${stamp}.csv`, lines.join("\n"), "text/csv");
  }

  function exportJson() {
    const payload = jsonRows ? jsonRows(rows) : rows;
    downloadBlob(`${filenameBase}-${stamp}.json`, JSON.stringify(payload, null, 2), "application/json");
  }

  return (
    <div className="csv-export-controls">
      <button type="button" className="btn-icon-label" onClick={exportCsv} disabled={rows.length === 0}>
        <IconDownload /> CSV
      </button>
      <button type="button" className="btn-icon-label" onClick={exportJson} disabled={rows.length === 0}>
        <IconDownload /> JSON
      </button>
      <button type="button" className="btn-icon-label" onClick={exportPdf} disabled={rows.length === 0}>
        <IconPrinter /> PDF
      </button>
    </div>
  );
}
