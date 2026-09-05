import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard from "./SettingsCard";

export default function AlertingCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [digestHour, setDigestHour] = useState(String(settings.digestEmailHourUtc));
  const [epss, setEpss] = useState(String(settings.epssAlertThreshold));
  const [backlog, setBacklog] = useState(String(settings.queueBacklogThresholdMinutes));
  const [offline, setOffline] = useState(String(settings.scannerOfflineThresholdMinutes));
  const [disappeared, setDisappeared] = useState(String(settings.hostDisappearedThresholdDays));
  const [coverage, setCoverage] = useState(String(settings.networkCoverageStaleDays));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDigestHour(String(settings.digestEmailHourUtc));
    setEpss(String(settings.epssAlertThreshold));
    setBacklog(String(settings.queueBacklogThresholdMinutes));
    setOffline(String(settings.scannerOfflineThresholdMinutes));
    setDisappeared(String(settings.hostDisappearedThresholdDays));
    setCoverage(String(settings.networkCoverageStaleDays));
  }, [settings]);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const hour = parseInt(digestHour, 10);
    const epssValue = parseFloat(epss);
    const backlogValue = parseInt(backlog, 10);
    const offlineValue = parseInt(offline, 10);
    const disappearedValue = parseInt(disappeared, 10);
    const coverageValue = parseInt(coverage, 10);
    if (Number.isNaN(hour) || hour < 0 || hour > 23) {
      setError("Digest hour must be between 0 and 23 (UTC).");
      return;
    }
    if (Number.isNaN(epssValue) || epssValue < 0 || epssValue > 1) {
      setError("EPSS threshold must be between 0 and 1.");
      return;
    }
    if (Number.isNaN(backlogValue) || backlogValue < 1) {
      setError("Queue backlog minutes must be 1 or greater.");
      return;
    }
    if (Number.isNaN(offlineValue) || offlineValue < 1) {
      setError("Scanner offline minutes must be 1 or greater.");
      return;
    }
    if (Number.isNaN(disappearedValue) || disappearedValue < 1) {
      setError("Host disappeared days must be 1 or greater.");
      return;
    }
    if (Number.isNaN(coverageValue) || coverageValue < 1) {
      setError("Network coverage window must be 1 day or greater.");
      return;
    }
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      onUpdated(
        await api.updateAppSettings({
          digestEmailHourUtc: hour,
          epssAlertThreshold: epssValue,
          queueBacklogThresholdMinutes: backlogValue,
          scannerOfflineThresholdMinutes: offlineValue,
          hostDisappearedThresholdDays: disappearedValue,
          networkCoverageStaleDays: coverageValue,
        })
      );
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
      title="Alerting thresholds"
      description={
        <>
          When the daily digest goes out, how likely a CVE has to be to exploit before a high-EPSS alert fires, how
          long a request may sit unclaimed before a queue-backlog alert, and the two thresholds for noticing something
          stopped existing. Set the host threshold comfortably longer than the schedule that covers it, or every host
          alerts between scans.
        </>
      }
      error={error}
      notice={saved && <p className="callout-success">Alerting settings saved.</p>}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Daily digest hour (UTC)
          <input className="input-number" type="number" min={0} max={23} step={1} value={digestHour} onChange={(e) => setDigestHour(e.target.value)} />
        </label>
        <label>
          EPSS alert threshold (0-1)
          <input className="input-number" type="number" min={0} max={1} step={0.05} value={epss} onChange={(e) => setEpss(e.target.value)} />
        </label>
        <label>
          Queue backlog after (minutes)
          <input className="input-number" type="number" min={1} step={1} value={backlog} onChange={(e) => setBacklog(e.target.value)} />
        </label>
        <label>
          Scanner offline after (minutes)
          <input className="input-number" type="number" min={1} step={1} value={offline} onChange={(e) => setOffline(e.target.value)} />
        </label>
        <label>
          Host disappeared after (days)
          <input className="input-number" type="number" min={1} step={1} value={disappeared} onChange={(e) => setDisappeared(e.target.value)} />
        </label>
        <label>
          Network coverage window (days)
          <input className="input-number" type="number" min={1} step={1} value={coverage} onChange={(e) => setCoverage(e.target.value)} />
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={saving}>
            <IconSave /> {saving ? "Saving..." : "Save alerting settings"}
          </button>
        </div>
      </form>
    </SettingsCard>
  );
}
