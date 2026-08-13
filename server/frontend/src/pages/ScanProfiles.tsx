import { FormEvent, useEffect, useState } from "react";
import { api, Me, ScanProfile } from "../api";
import { IconEdit, IconPlus, IconSave, IconTrash, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { ADDITIONAL_SAFE_NSE_SCRIPTS, DEFAULT_NSE_SCRIPTS } from "../lib/nseScripts";

// Admin-only, like Excludes/Webhooks/Scanner Agents - lets an admin build
// a named, reusable "Custom" scan profile (a specific set of NSE
// scripts) selectable everywhere a scan gets triggered (Schedule Scans,
// the Rescan popup). "Default" and "All Safe Modules" are the two other
// profile choices - built into the scanner itself (see CLAUDE.md's Scan
// Profiles section), not editable here.
export default function ScanProfiles({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [selectedScripts, setSelectedScripts] = useState<Set<string>>(new Set());
  const [editingId, setEditingId] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setProfiles(await api.scanProfiles());
    } finally {
      setLoading(false);
    }
  }

  function toggleScript(script: string) {
    setSelectedScripts((prev) => {
      const next = new Set(prev);
      if (next.has(script)) next.delete(script);
      else next.add(script);
      return next;
    });
  }

  function resetForm() {
    setEditingId(null);
    setName("");
    setSelectedScripts(new Set());
  }

  function startEdit(p: ScanProfile) {
    setEditingId(p.id);
    setName(p.name);
    setSelectedScripts(new Set(p.nse_scripts));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || selectedScripts.size === 0) return;
    setError(null);
    try {
      if (editingId) {
        await api.updateScanProfile(editingId, { name: name.trim(), nseScripts: [...selectedScripts] });
      } else {
        await api.createScanProfile(name.trim(), [...selectedScripts]);
      }
      resetForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save scan profile");
    }
  }

  async function handleDelete(p: ScanProfile) {
    if (!window.confirm(`Delete scan profile "${p.name}"? Schedules/rescans that already used it keep their own snapshot - only future picks are affected.`)) {
      return;
    }
    await api.deleteScanProfile(p.id);
    if (editingId === p.id) resetForm();
    await load();
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Scan Profiles</h2>
      <p className="host-meta">
        Which NSE scripts a scan runs - "Default" and "All Safe Modules" are always available and built into the
        scanner itself; a Custom profile here lets you pick your own set, selectable anywhere a scan gets
        triggered.
      </p>

      {error && <p className="error">{error}</p>}

      <form className="schedule-form" onSubmit={handleSubmit}>
        <label>
          Name
          <input placeholder="e.g. web-only" value={name} onChange={(e) => setName(e.target.value)} />
        </label>

        <div className="column-toggles">
          Default ({DEFAULT_NSE_SCRIPTS.length}):
          {DEFAULT_NSE_SCRIPTS.map((script) => (
            <label key={script}>
              <input type="checkbox" checked={selectedScripts.has(script)} onChange={() => toggleScript(script)} />
              {script}
            </label>
          ))}
        </div>

        <details>
          <summary>Additional Safe Modules ({ADDITIONAL_SAFE_NSE_SCRIPTS.length})</summary>
          <div className="column-toggles">
            {ADDITIONAL_SAFE_NSE_SCRIPTS.map((script) => (
              <label key={script}>
                <input type="checkbox" checked={selectedScripts.has(script)} onChange={() => toggleScript(script)} />
                {script}
              </label>
            ))}
          </div>
        </details>

        <p className="host-meta">{selectedScripts.size} script(s) selected</p>

        <button type="submit" className="btn-icon-label" disabled={!name.trim() || selectedScripts.size === 0}>
          {editingId ? (
            <>
              <IconSave /> Save changes
            </>
          ) : (
            <>
              <IconPlus /> Create
            </>
          )}
        </button>
        {editingId && (
          <button type="button" className="link-button btn-icon-label" onClick={resetForm}>
            <IconX /> Cancel
          </button>
        )}
      </form>

      {loading ? (
        <p>Loading...</p>
      ) : profiles.length === 0 ? (
        <p className="empty">No custom scan profiles created yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Scripts</th>
              <th>Created by</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {profiles.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td className="banner">{p.nse_scripts.join(", ")}</td>
                <td>{p.created_by ?? "-"}</td>
                <td>
                  <div className="actions-cell">
                    <button className="btn-icon-label" onClick={() => startEdit(p)}>
                      <IconEdit /> Edit
                    </button>
                    <button className="btn-icon-label" onClick={() => handleDelete(p)}>
                      <IconTrash /> Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
