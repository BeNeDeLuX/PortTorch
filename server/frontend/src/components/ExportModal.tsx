import { HostFilters, hostsExportJsonUrl, hostsExportUrl } from "../api";
import Modal from "./Modal";

// Opened from the Dashboard's "Export data" link, same Modal shell as the
// scan progress "Details" popup - three download options sharing the
// dashboard's current filters, rather than a single link + a separate
// row-shape <select> next to it.
export default function ExportModal({ filters, onClose }: { filters: HostFilters; onClose: () => void }) {
  return (
    <Modal title="Export data" onClose={onClose}>
      <p className="host-meta">Exports whatever the dashboard's current search/filters are scoped to.</p>
      <div className="export-options">
        <div className="export-option">
          <div>
            <strong>CSV - 1 row per host</strong>
            <div className="host-meta">Summary: one row per host, with an open-port count.</div>
          </div>
          <a className="export-link" href={hostsExportUrl(filters, "host")} download>
            Download
          </a>
        </div>
        <div className="export-option">
          <div>
            <strong>CSV - 1 row per host+port</strong>
            <div className="host-meta">Detailed: one row per open port, host columns repeated per row.</div>
          </div>
          <a className="export-link" href={hostsExportUrl(filters, "port")} download>
            Download
          </a>
        </div>
        <div className="export-option">
          <div>
            <strong>JSON</strong>
            <div className="host-meta">One object per host, with a nested list of its open ports.</div>
          </div>
          <a className="export-link" href={hostsExportJsonUrl(filters)} download>
            Download
          </a>
        </div>
      </div>
    </Modal>
  );
}
