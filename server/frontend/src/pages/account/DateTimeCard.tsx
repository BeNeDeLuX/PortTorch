import { FormEvent, useEffect, useState } from "react";
import { Me, UserPreferences, api } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "../../components/SettingsCard";

export default function DateTimeCard({
  me,
  timezones,
  onSaved,
}: {
  me: Me;
  timezones: string[];
  onSaved: (p: UserPreferences) => void;
}) {
  const [timezone, setTimezone] = useState(me.preferences.timezone ?? "");
  const [timeFormat, setTimeFormat] = useState(me.preferences.timeFormat ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setTimezone(me.preferences.timezone ?? "");
    setTimeFormat(me.preferences.timeFormat ?? "");
  }, [me.preferences.timezone, me.preferences.timeFormat]);

  const dirty = timezone !== (me.preferences.timezone ?? "") || timeFormat !== (me.preferences.timeFormat ?? "");

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const updated = await api.updatePreferences({
        timezone: timezone || null,
        timeFormat: timeFormat ? (timeFormat as "h12" | "h24") : null,
      });
      onSaved(updated);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SettingsCard
      title="Date and time"
      description="How every timestamp in the dashboard is displayed. Everything is stored in UTC; this only changes what you read."
      error={error}
    >
      <form className="settings-form" onSubmit={save}>
        <label>
          Timezone
          <select value={timezone} onChange={(e) => setTimezone(e.target.value)} disabled={busy}>
            <option value="">Browser default</option>
            {timezones.map((tz) => (
              <option key={tz} value={tz}>
                {tz}
              </option>
            ))}
          </select>
        </label>
        <label>
          Time format
          <select value={timeFormat} onChange={(e) => setTimeFormat(e.target.value)} disabled={busy}>
            <option value="">Browser/locale default</option>
            <option value="h12">12-hour (1:30 PM)</option>
            <option value="h24">24-hour (13:30)</option>
          </select>
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={busy || !dirty}>
            <IconSave /> {busy ? "Saving..." : "Save"}
          </button>
          <SaveState saved={saved} dirty={dirty} />
        </div>
      </form>
      <p className="host-meta">
        A new timezone applies on your next page load rather than instantly - the pages already rendered keep the
        format they were drawn with.
      </p>
    </SettingsCard>
  );
}
