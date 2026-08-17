import { FormEvent, KeyboardEvent, useEffect, useState } from "react";
import { api, Me, NucleiProfile } from "../api";
import { IconEdit, IconPlus, IconSave, IconTrash, IconWarning, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";

const KNOWN_SEVERITIES = ["unknown", "info", "low", "medium", "high", "critical"];

// A tag/excluded-tag chip input - free text, not checkboxes, since
// nuclei's own tag taxonomy has thousands of entries (confirmed by
// testing - see CLAUDE.md's nuclei section) and grows with every template
// release, unlike NSE's small, fixed script list. An unrecognized tag is
// harmless (matches zero templates), so there's nothing to validate
// client-side beyond basic shape.
function TagChipInput({ tags, onChange, placeholder }: { tags: string[]; onChange: (tags: string[]) => void; placeholder: string }) {
  const [draft, setDraft] = useState("");

  function commit() {
    const value = draft.trim().toLowerCase();
    if (value && !tags.includes(value)) onChange([...tags, value]);
    setDraft("");
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit();
    } else if (e.key === "Backspace" && draft === "" && tags.length > 0) {
      onChange(tags.slice(0, -1));
    }
  }

  return (
    <div className="tag-chip-input">
      {tags.map((t) => (
        <span key={t} className="chip active">
          {t}
          <button type="button" className="link-button" onClick={() => onChange(tags.filter((x) => x !== t))}>
            <IconX size={11} />
          </button>
        </span>
      ))}
      <input
        placeholder={placeholder}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={commit}
      />
    </div>
  );
}

// Admin-only, like Scan Profiles - lets an admin build a named, reusable
// "Custom" nuclei profile (tags/severities/excluded tags) selectable
// everywhere a scan gets triggered. "Off" and "Safe" are the two other
// choices, resolved entirely scanner-side (see CLAUDE.md's nuclei
// section) - not editable here, since neither has anything a profile row
// could represent ("Safe" is just a fixed exclude-tags expression, no
// admin-curated content).
export default function NucleiProfiles({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [profiles, setProfiles] = useState<NucleiProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [severities, setSeverities] = useState<Set<string>>(new Set());
  const [excludedTags, setExcludedTags] = useState<string[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setProfiles(await api.nucleiProfiles());
    } finally {
      setLoading(false);
    }
  }

  function toggleSeverity(s: string) {
    setSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function resetForm() {
    setEditingId(null);
    setName("");
    setTags([]);
    setSeverities(new Set());
    setExcludedTags([]);
  }

  function startEdit(p: NucleiProfile) {
    setEditingId(p.id);
    setName(p.name);
    setTags(p.tags);
    setSeverities(new Set(p.severities));
    setExcludedTags(p.excluded_tags);
  }

  const hasSelection = tags.length > 0 || severities.size > 0;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !hasSelection) return;
    setError(null);
    try {
      if (editingId) {
        await api.updateNucleiProfile(editingId, { name: name.trim(), tags, severities: [...severities], excludedTags });
      } else {
        await api.createNucleiProfile(name.trim(), tags, [...severities], excludedTags);
      }
      resetForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save nuclei profile");
    }
  }

  async function handleDelete(p: NucleiProfile) {
    if (
      !window.confirm(
        `Delete nuclei profile "${p.name}"? Schedules/rescans that already used it keep their own snapshot - only future picks are affected.`
      )
    ) {
      return;
    }
    await api.deleteNucleiProfile(p.id);
    if (editingId === p.id) resetForm();
    await load();
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Nuclei Profiles</h2>
      <p className="host-meta">
        Which nuclei templates a scan runs against its discovered HTTP(S) ports - "Off" (default) and "Safe" are
        always available and resolved by the scanner itself; a Custom profile here lets you pick your own
        tags/severities, selectable anywhere a scan gets triggered.
      </p>

      <div className="callout-danger">
        <IconWarning />
        <span>
          A Custom profile's tags aren't restricted the way "Safe" is - depending on the tags you pick, it can
          include intrusive, exploit-attempting, or disruptive templates. Only ever run one against systems you're
          explicitly authorized to test this way.
        </span>
      </div>

      {error && <p className="error">{error}</p>}

      <form className="schedule-form" onSubmit={handleSubmit}>
        <label>
          Name
          <input placeholder="e.g. exposures-only" value={name} onChange={(e) => setName(e.target.value)} />
        </label>

        <label>
          Tags
          <TagChipInput tags={tags} onChange={setTags} placeholder="e.g. exposure, config, cve (Enter to add)" />
        </label>

        <label>
          Excluded tags
          <TagChipInput tags={excludedTags} onChange={setExcludedTags} placeholder="e.g. dos, fuzz, intrusive" />
        </label>

        <details open className="form-fullwidth-section">
          <summary>Severities ({severities.size}/{KNOWN_SEVERITIES.length})</summary>
          <div className="checkbox-list">
            {KNOWN_SEVERITIES.map((s) => (
              <label key={s}>
                <input type="checkbox" checked={severities.has(s)} onChange={() => toggleSeverity(s)} />
                {s}
              </label>
            ))}
          </div>
        </details>

        <p className="host-meta">
          {tags.length} tag(s), {severities.size} severity/severities selected - matches any template with at least
          one selected tag or severity.
        </p>

        <button type="submit" className="btn-icon-label" disabled={!name.trim() || !hasSelection}>
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
        <p className="empty">No custom nuclei profiles created yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Tags</th>
              <th>Severities</th>
              <th>Excluded tags</th>
              <th>Created by</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {profiles.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td className="banner">{p.tags.join(", ") || "-"}</td>
                <td className="banner">{p.severities.join(", ") || "-"}</td>
                <td className="banner">{p.excluded_tags.join(", ") || "-"}</td>
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
