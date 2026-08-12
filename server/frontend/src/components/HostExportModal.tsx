import { HostDetail } from "../api";
import { IconDownload, IconPrinter } from "./icons";
import { csvEscape, downloadBlob } from "../lib/download";
import Modal from "./Modal";

// Host Detail's counterpart to the Dashboard's ExportModal - same Modal
// shell and "Export data" naming, but the data is already loaded on screen
// (this one host's record + open ports, with fields the fleet-wide export
// doesn't carry at all, like banners/CPEs/CVEs), so both options build the
// file client-side rather than linking to a backend URL.
export default function HostExportModal({ data, onClose }: { data: HostDetail; onClose: () => void }) {
  function exportCsv() {
    const lines = [
      "port,protocol,service_name,service_product,service_version,extra_info,os_type,cpes,banner,observed_at,cves",
      ...data.ports.map((p) =>
        [
          p.port,
          p.protocol,
          p.service_name,
          p.service_product,
          p.service_version,
          p.extra_info,
          p.os_type,
          (p.cpes ?? []).join("; "),
          p.banner,
          p.observed_at,
          p.vulnerabilities.map((v) => v.id).join("; "),
        ]
          .map(csvEscape)
          .join(",")
      ),
    ];
    downloadBlob(`host-${data.host.ip}-ports.csv`, lines.join("\r\n"), "text/csv;charset=utf-8");
  }

  function exportJson() {
    downloadBlob(`host-${data.host.ip}.json`, JSON.stringify({ host: data.host, ports: data.ports }, null, 2), "application/json");
  }

  function exportPdf() {
    // No PDF library - the browser's own print-to-PDF against this page's
    // current DOM (styles.css's @media print block hides nav/forms/buttons
    // and forces light-mode colors) already produces exactly "the page's
    // view, with the screenshots" this option is for.
    window.print();
  }

  return (
    <Modal title="Export data" onClose={onClose}>
      <p className="host-meta">Exports this host's current open ports and details.</p>
      <div className="export-options">
        <div className="export-option">
          <div>
            <strong>CSV - open ports</strong>
            <div className="host-meta">One row per open port, including banner/CPEs/CVE ids.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportCsv}>
            <IconDownload /> Download
          </button>
        </div>
        <div className="export-option">
          <div>
            <strong>JSON</strong>
            <div className="host-meta">The full host record plus its open ports.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportJson}>
            <IconDownload /> Download
          </button>
        </div>
        <div className="export-option">
          <div>
            <strong>PDF</strong>
            <div className="host-meta">A snapshot of this page as shown, including screenshots.</div>
          </div>
          <button type="button" className="export-link btn-icon-label" onClick={exportPdf}>
            <IconPrinter /> Print / Save as PDF
          </button>
        </div>
      </div>
    </Modal>
  );
}
