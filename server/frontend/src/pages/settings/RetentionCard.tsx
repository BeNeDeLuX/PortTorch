import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave, IconTrash } from "../../components/icons";
import SettingsCard, { SaveState } from "./SettingsCard";

export default function RetentionCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [days, setDays] = useState(String(settings.hostRetentionDays));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    setDays(String(settings.hostRetentionDays));
  }, [settings.hostRetentionDays]);

  const dirty = days !== String(settings.hostRetentionDays);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const value = parseInt(days, 10);
    if (Number.isNaN(value) || value < 0) {
      setError("Enter a whole number of days, 0 or greater (0 disables the sweep).");
      return;
    }
    setError(null);
    setSaving(true);
    try {
      onUpdated(await api.updateAppSettings({ hostRetentionDays: value }));
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  async function handleCleanupNow() {
    if (
      !window.confirm(
        `Permanently delete every host not seen in the last ${settings.hostRetentionDays} day(s) (along with all their ports/screenshots/tags/comments/certificates), and every audit log entry older than the same window? This runs the same purge the hourly sweep does, right now, and can't be undone.`
      )
    ) {
      return;
    }
    setError(null);
    setResult(null);
    setRunning(true);
    try {
      const r = await api.runRetentionSweepNow();
      const parts = [
        r.purgedHosts === 0 ? "no hosts" : `${r.purgedHosts} host(s)`,
        r.purgedAuditLogEntries === 0 ? "no audit log entries" : `${r.purgedAuditLogEntries} audit log entry/entries`,
        r.purgedScanLogs === 0 ? "no scan logs" : `${r.purgedScanLogs} scan log(s)`,
        r.purgedScreenshots === 0 ? "no screenshots" : `${r.purgedScreenshots} screenshot(s)`,
      ];
      setResult(`Purged ${parts.join(" and ")}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run cleanup");
    } finally {
      setRunning(false);
    }
  }

  return (
    <SettingsCard
      title="Host Retention"
      description={
        <>
          Hosts not seen for this many days are purged every hour, along with all their history - ports, screenshots,
          tags, comments, certificates. Audit log entries older than the same window go in the same sweep. 0 disables
          it entirely.
        </>
      }
      error={error}
      notice={result && <p className="callout-success">{result}</p>}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Keep hosts for
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={0}
              step={1}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              aria-label="Host retention days"
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
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={handleCleanupNow} disabled={running}>
          <IconTrash /> {running ? "Cleaning up..." : "Clean up now"}
        </button>
      </div>
    </SettingsCard>
  );
}
