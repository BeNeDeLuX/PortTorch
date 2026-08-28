import { FormEvent, useEffect, useState } from "react";
import { api, ScannerAgent, ScannerTunable } from "../api";
import { IconSave, IconX } from "./icons";
import Modal from "./Modal";

// Editing part of a scanner's config.yaml from the dashboard instead of
// over SSH. The field list comes from the server's own allowlist rather
// than being repeated here, so the form and the validation can't disagree
// about which settings exist or what their bounds are.
//
// A blank field means "no override" - the scanner falls back to whatever
// its config.yaml says. That's why the placeholder reads "config.yaml"
// rather than showing a default value: the webserver genuinely doesn't
// know what's in that file, and printing a guessed default as if it were
// the current value would be a lie.
export default function ScannerConfigModal({
  agent,
  onSaved,
  onClose,
}: {
  agent: ScannerAgent;
  onSaved: () => void;
  onClose: () => void;
}) {
  const [tunables, setTunables] = useState<ScannerTunable[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .scannerTunables()
      .then(setTunables)
      .catch(() => setError("Could not load the list of settings."));
    const current = agent.config_overrides ?? {};
    setValues(Object.fromEntries(Object.entries(current).map(([k, v]) => [k, String(v)])));
  }, [agent.id]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const settings: Record<string, number> = {};
    for (const t of tunables) {
      const raw = (values[t.key] ?? "").trim();
      if (raw === "") continue; // blank = no override
      const n = Number(raw);
      if (!Number.isInteger(n) || n < t.min || n > t.max) {
        setError(`${t.label} must be a whole number between ${t.min} and ${t.max}.`);
        return;
      }
      settings[t.key] = n;
    }
    setError(null);
    setSaving(true);
    try {
      await api.setScannerConfig(agent.id, settings);
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save these settings.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal title={`Configure ${agent.name}`} onClose={onClose}>
      <p className="empty">
        Overrides this scanner's own config.yaml. Leave a field blank to use whatever that file says. The scanner picks
        changes up on its next poll and applies them in memory - its config file is never rewritten, so a restart falls
        back to the file and the override is simply fetched again.
      </p>
      <p className="empty">
        Only tuning is settable here. Connection details, binary paths and the API key deliberately aren't: a wrong
        value there would cut this scanner off with no way to reach it and fix it.
      </p>

      {error && <p className="error">{error}</p>}

      <form className="settings-form" onSubmit={handleSubmit}>
        {tunables.map((t) => (
          <label key={t.key}>
            {t.label}
            <input
              className="input-number"
              type="number"
              min={t.min}
              max={t.max}
              step={1}
              placeholder="config.yaml"
              value={values[t.key] ?? ""}
              onChange={(e) => setValues((prev) => ({ ...prev, [t.key]: e.target.value }))}
            />
            <span className="empty">{t.help}</span>
          </label>
        ))}
        <div className="inline-form">
          <button type="submit" className="btn-icon-label" disabled={saving}>
            <IconSave /> {saving ? "Saving..." : "Save"}
          </button>
          <button type="button" className="btn-icon-label" onClick={onClose}>
            <IconX /> Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}
