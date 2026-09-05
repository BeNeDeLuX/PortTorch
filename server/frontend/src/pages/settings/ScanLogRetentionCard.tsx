import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "./SettingsCard";

export default function ScanLogRetentionCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [days, setDays] = useState(String(settings.scanLogRetentionDays));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDays(String(settings.scanLogRetentionDays));
  }, [settings.scanLogRetentionDays]);

  const dirty = days !== String(settings.scanLogRetentionDays);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const value = parseInt(days, 10);
    if (Number.isNaN(value) || value < 0) {
      setError("Enter a whole number of days, 0 or greater (0 keeps logs forever).");
      return;
    }
    setError(null);
    setSaving(true);
    try {
      onUpdated(await api.updateAppSettings({ scanLogRetentionDays: value }));
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SettingsCard
      title="Scan Log Retention"
      description={
        <>
          A finished scan's pushed log output (Scan History's "Details" popup) is deleted after this many days; the
          scan itself stays with its target, duration and counts. These are by far the largest rows in the database and
          nothing else prunes them, so 0 means unbounded growth - a busy fleet can add several GB a year. A running
          scan's live log is never touched.
        </>
      }
      error={error}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Keep logs for
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={0}
              step={1}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              aria-label="Scan log retention days"
            />
            <span className="empty">days</span>
          </span>
        </label>
        <div className="inline-actions">
          <button type="submit" className="btn-icon-label" disabled={saving || !dirty}>
            <IconSave /> {saving ? "Saving..." : "Save"}
          </button>
          <SaveState saved={saved} dirty={dirty} />
        </div>
      </form>
    </SettingsCard>
  );
}
