import { IconDownload, IconPrinter } from "./icons";
import { csvEscape, downloadBlob } from "../lib/download";
import Modal from "./Modal";

type DigestExportHost = {
  id: string;
  ip: string;
  hostname: string | null;
  observedAt: string;
  scannerAgentName: string | null;
};

type DigestExportPort = { port: number; service_name: string | null };

// Digest's counterpart to Host Detail's export modal (same Modal shell,
// same three options) - built from whatever the Digest page's own
// search/category filters are currently showing, not the unfiltered
// API response, so the export always matches what's on screen.
export default function DigestExportModal({
  from,
  to,
  newHosts,
  changedHosts,
  onClose,
}: {
  from: string;
  to: string;
  newHosts: DigestExportHost[];
  changedHosts: Array<DigestExportHost & { newlyOpen: DigestExportPort[]; newlyClosed: DigestExportPort[] }>;
  onClose: () => void;
}) {
  function portLabel(p: DigestExportPort): string {
    return p.port + (p.service_name ? `/${p.service_name}` : "");
  }

  function exportCsv() {
    const lines = ["change_type,host,port,service_name,observed_at,scanner_agent"];
    for (const h of newHosts) {
      lines.push(["new_host", h.hostname || h.ip, "", "", h.observedAt, h.scannerAgentName].map(csvEscape).join(","));
    }
    for (const h of changedHosts) {
      for (const p of h.newlyOpen) {
        lines.push(
          ["newly_open", h.hostname || h.ip, p.port, p.service_name, h.observedAt, h.scannerAgentName]
            .map(csvEscape)
            .join(",")
        );
      }
      for (const p of h.newlyClosed) {
        lines.push(
          ["newly_closed", h.hostname || h.ip, p.port, p.service_name, h.observedAt, h.scannerAgentName]
            .map(csvEscape)
            .join(",")
        );
      }
    }
    downloadBlob("digest.csv", lines.join("\r\n"), "text/csv;charset=utf-8");
  }

  function exportJson() {
    downloadBlob("digest.json", JSON.stringify({ from, to, newHosts, changedHosts }, null, 2), "application/json");
  }

  function exportPdf() {
    // No PDF library - same browser print-to-PDF approach as Host Detail's
    // export, against this page's current filtered view (styles.css's
    // @media print block hides the search/filter/date controls and
    // reveals a plain-text from/to line in their place).
    window.print();
  }

  return (
    <Modal title="Export data" onClose={onClose}>
      <p className="host-meta">
        Exports the digest as currently filtered ({newHosts.length + changedHosts.length} host
        {newHosts.length + changedHosts.length === 1 ? "" : "s"} shown).
      </p>
      <div className="export-options">
        <div className="export-option">
          <div>
            <strong>CSV</strong>
            <div className="host-meta">One row per new host or port change.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportCsv}>
            <IconDownload /> Download
          </button>
        </div>
        <div className="export-option">
          <div>
            <strong>JSON</strong>
            <div className="host-meta">New hosts and changed hosts, as currently filtered.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportJson}>
            <IconDownload /> Download
          </button>
        </div>
        <div className="export-option">
          <div>
            <strong>PDF</strong>
            <div className="host-meta">A snapshot of this page as shown.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportPdf}>
            <IconPrinter /> Print / Save as PDF
          </button>
        </div>
      </div>
    </Modal>
  );
}
