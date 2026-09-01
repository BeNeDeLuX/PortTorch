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
// its config.yaml says. That's why the placeholder still reads
// "config.yaml" and not a number: the webserver genuinely cannot read
// that file, and printing a value into the field as if it were the
// current one would be a lie.
//
// Beside each field is the value that applies when it is left blank. A
// serve-mode scanner reports its own config.yaml (agent.base_config, see
// PUT /api/ingest/config-report), so for those the real number is shown;
// where it hasn't reported - an older build, or one that has not polled
// yet - the shipped default from the allowlist stands in, and is labelled
// as such rather than passed off as this scanner's value.
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
        {agent.base_config
          ? "The value beside each field is what this scanner's own config.yaml says - it reported them itself - so that is exactly what applies when you leave the field blank."
          : "This scanner hasn't reported its own config.yaml yet, so the values beside the fields are what a fresh install uses. If that file was edited on the host, its value applies instead. A scanner running in serve mode reports the real ones on its next poll."}
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
              placeholder={
                agent.base_config?.[t.key] !== undefined ? String(agent.base_config[t.key]) : "config.yaml"
              }
              value={values[t.key] ?? ""}
              onChange={(e) => setValues((prev) => ({ ...prev, [t.key]: e.target.value }))}
            />
            <span className="empty">
              {agent.base_config?.[t.key] !== undefined ? (
                <span className="tunable-default" title="Reported by this scanner from its own config.yaml">
                  config.yaml: {agent.base_config[t.key]}
                </span>
              ) : (
                <span className="tunable-default" title="This scanner has not reported its own config.yaml - this is what a fresh install uses">
                  Default {t.defaultValue}
                </span>
              )}{" "}
              · {t.help}
            </span>
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
