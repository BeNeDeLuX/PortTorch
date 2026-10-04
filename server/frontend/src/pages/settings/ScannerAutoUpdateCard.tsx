import { useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";

// The fleet-wide default for scanner auto-update. Each scanner can pin it
// on or off on the Scanner Agents page; this is what the rest follow.
export default function ScannerAutoUpdateCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleToggle() {
    setError(null);
    setSaving(true);
    try {
      onUpdated(await api.updateAppSettings({ scannerAutoUpdate: !settings.scannerAutoUpdate }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SettingsCard
      title="Scanner auto-update"
      description={
        <>
          When on, a scanner behind the latest published release is asked to update itself within five minutes, the same
          as clicking Update on the Scanner Agents page. It applies the update once it is idle, so a running scan is never
          interrupted. A failed update is not retried automatically - it waits for an admin. Individual scanners can be
          set to always or never on the Scanner Agents page.
        </>
      }
      error={error}
    >
      <p className="settings-state">
        Fleet default: <strong>{settings.scannerAutoUpdate ? "on" : "off"}</strong>
      </p>
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={handleToggle} disabled={saving}>
          <IconSave /> {settings.scannerAutoUpdate ? "Turn off" : "Turn on"}
        </button>
      </div>
    </SettingsCard>
  );
}
