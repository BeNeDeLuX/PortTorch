import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "./SettingsCard";

// The two scan-warning thresholds share one card and one Save. They were
// two sections with two forms and two Save buttons, both writing the same
// PATCH /api/settings/app - and in a card grid a single form cannot span
// two cards anyway, so keeping them apart would have meant keeping the
// duplicate round trip for no gain.
export default function ScanningCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [stale, setStale] = useState(String(settings.staleScanThresholdMinutes));
  const [queue, setQueue] = useState(String(settings.scanQueueWarningThreshold));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Re-sync whenever the stored values change under us - another card's
  // save returns the whole settings object, so this keeps the dirty
  // marker honest rather than showing "unsaved" against a stale copy.
  useEffect(() => {
    setStale(String(settings.staleScanThresholdMinutes));
    setQueue(String(settings.scanQueueWarningThreshold));
  }, [settings.staleScanThresholdMinutes, settings.scanQueueWarningThreshold]);

  const dirty =
    stale !== String(settings.staleScanThresholdMinutes) || queue !== String(settings.scanQueueWarningThreshold);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const minutes = parseInt(stale, 10);
    const count = parseInt(queue, 10);
    if (Number.isNaN(minutes) || minutes < 1) {
      setError("Stale scan threshold must be a whole number of minutes, 1 or greater.");
      return;
    }
    if (Number.isNaN(count) || count < 1) {
      setError("Queue warning must be a whole number of pending requests, 1 or greater.");
      return;
    }
    setError(null);
    setSaving(true);
    try {
      onUpdated(
        await api.updateAppSettings({ staleScanThresholdMinutes: minutes, scanQueueWarningThreshold: count })
      );
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SettingsCard
      title="Scan warnings"
      description={
        <>
          A running scan is flagged stale once its scanner stops sending progress for this long - a slow scan won't
          trip it as long as the heartbeat keeps arriving. Fleet Health's Scan Queue card warns once this many requests
          are waiting; a single request stuck 30+ minutes still escalates to critical regardless, since that suggests a
          scanner stopped polling. Both are display and alert hints - nothing is deleted or reassigned.
        </>
      }
      error={error}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Stale scan after
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={1}
              step={1}
              value={stale}
              onChange={(e) => setStale(e.target.value)}
              aria-label="Stale scan threshold minutes"
            />
            <span className="empty">minutes</span>
          </span>
        </label>
        <label>
          Queue warning at
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={1}
              step={1}
              value={queue}
              onChange={(e) => setQueue(e.target.value)}
              aria-label="Scan queue warning threshold"
            />
            <span className="empty">pending requests</span>
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
