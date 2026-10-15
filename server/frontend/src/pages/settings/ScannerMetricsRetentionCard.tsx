import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "../../components/SettingsCard";

// Two windows because the two tables age differently: minute samples are
// what a 24-hour or 7-day chart reads, the hourly roll-up is what keeps a
// year of history at 1/60th of the rows.
export default function ScannerMetricsRetentionCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [raw, setRaw] = useState(String(settings.scannerMetricsRawDays));
  const [hourly, setHourly] = useState(String(settings.scannerMetricsHourlyDays));
  const [cpu, setCpu] = useState(String(settings.cpuAlertPercent));
  const [mem, setMem] = useState(String(settings.memAlertPercent));
  const [disk, setDisk] = useState(String(settings.diskLowPercent));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRaw(String(settings.scannerMetricsRawDays));
    setHourly(String(settings.scannerMetricsHourlyDays));
    setCpu(String(settings.cpuAlertPercent));
    setMem(String(settings.memAlertPercent));
    setDisk(String(settings.diskLowPercent));
  }, [settings.scannerMetricsRawDays, settings.scannerMetricsHourlyDays, settings.cpuAlertPercent, settings.memAlertPercent, settings.diskLowPercent]);

  const dirty =
    raw !== String(settings.scannerMetricsRawDays) ||
    hourly !== String(settings.scannerMetricsHourlyDays) ||
    cpu !== String(settings.cpuAlertPercent) ||
    mem !== String(settings.memAlertPercent) ||
    disk !== String(settings.diskLowPercent);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      onUpdated(
        await api.updateAppSettings({
          scannerMetricsRawDays: parseInt(raw, 10),
          scannerMetricsHourlyDays: parseInt(hourly, 10),
          cpuAlertPercent: parseInt(cpu, 10),
          memAlertPercent: parseInt(mem, 10),
          diskLowPercent: parseInt(disk, 10),
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
      title="Scanner Metrics & Load Alerts"
      description={
        <>
          Each scanner reports CPU, memory and network once a minute. Minute samples are kept for the first window and
          serve the short charts; older data survives only as hourly averages and peaks, kept for the second window.
          A year of hourly data is about 9,000 rows per scanner. The alert lines decide when a scanner counts as
          overloaded (averaged over 15 minutes), when a scan is flagged as run on an overloaded host, and when a
          scanner's or this webserver's disk counts as running out.
        </>
      }
      error={error}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Keep minute samples for
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={1}
              max={90}
              step={1}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              aria-label="Scanner metrics minute sample retention days"
            />
            <span className="empty">days</span>
          </span>
        </label>
        <label>
          Keep hourly history for
          <span className="settings-num-row">
            <input
              className="input-number"
              type="number"
              min={7}
              max={1825}
              step={1}
              value={hourly}
              onChange={(e) => setHourly(e.target.value)}
              aria-label="Scanner metrics hourly retention days"
            />
            <span className="empty">days</span>
          </span>
        </label>
        {(
          [
            ["Alert at CPU", cpu, setCpu, 50, 100, "%", "CPU alert threshold percent"],
            ["Alert at memory", mem, setMem, 50, 100, "%", "Memory alert threshold percent"],
            ["Alert below free disk", disk, setDisk, 1, 50, "% free", "Disk free alert threshold percent"],
          ] as const
        ).map(([label, value, set, min, max, unit, aria]) => (
          <label key={aria}>
            {label}
            <span className="settings-num-row">
              <input
                className="input-number"
                type="number"
                min={min}
                max={max}
                step={1}
                value={value}
                onChange={(e) => set(e.target.value)}
                aria-label={aria}
              />
              <span className="empty">{unit}</span>
            </span>
          </label>
        ))}
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
