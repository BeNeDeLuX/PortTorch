import { useState } from "react";
import { HostFilters, hostsExportJsonUrl, hostsExportUrl } from "../api";
import Modal from "./Modal";

// Opened from the Dashboard's "Export data" link, same Modal shell as the
// scan progress "Details" popup - three download options sharing the
// dashboard's current filters, rather than a single link + a separate
// row-shape <select> next to it.
//
// selectedCount > 0 means the Dashboard's bulk-select checkboxes have at
// least one host checked - offering a choice between "everything the
// current filters match" and "just what I selected" rather than always
// exporting the full filtered set, which could be a very different
// (usually much larger) set than what the user actually checked.
export default function ExportModal({
  filters,
  selectedIds,
  onClose,
}: {
  filters: HostFilters;
  selectedIds: string[];
  onClose: () => void;
}) {
  const [onlySelected, setOnlySelected] = useState(selectedIds.length > 0);
  const scopeIds = onlySelected ? selectedIds : undefined;

  return (
    <Modal title="Export data" onClose={onClose}>
      {selectedIds.length > 0 ? (
        <label className="export-scope-toggle">
          <input type="checkbox" checked={onlySelected} onChange={(e) => setOnlySelected(e.target.checked)} />
          Export only the {selectedIds.length} selected host{selectedIds.length === 1 ? "" : "s"} (instead of
          everything the current search/filters match)
        </label>
      ) : (
        <p className="host-meta">Exports whatever the dashboard's current search/filters are scoped to.</p>
      )}
      <div className="export-options">
        <div className="export-option">
          <div>
            <strong>CSV - 1 row per host</strong>
            <div className="host-meta">Summary: one row per host, with an open-port count.</div>
          </div>
          <a className="export-link" href={hostsExportUrl(filters, "host", scopeIds)} download>
            Download
          </a>
        </div>
        <div className="export-option">
          <div>
            <strong>CSV - 1 row per host+port</strong>
            <div className="host-meta">Detailed: one row per open port, host columns repeated per row.</div>
          </div>
          <a className="export-link" href={hostsExportUrl(filters, "port", scopeIds)} download>
            Download
          </a>
        </div>
        <div className="export-option">
          <div>
            <strong>JSON</strong>
            <div className="host-meta">One object per host, with a nested list of its open ports.</div>
          </div>
          <a className="export-link" href={hostsExportJsonUrl(filters, scopeIds)} download>
            Download
          </a>
        </div>
      </div>
    </Modal>
  );
}
