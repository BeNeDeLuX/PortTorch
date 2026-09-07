import { FormEvent, useEffect, useState } from "react";
import { Me, ScannerAgent, UserPreferences, api } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard, { SaveState } from "../../components/SettingsCard";

export default function DashboardCard({
  me,
  agents,
  onSaved,
}: {
  me: Me;
  agents: ScannerAgent[];
  onSaved: (p: UserPreferences) => void;
}) {
  const currentPageSize = me.preferences.hostsPageSize ? String(me.preferences.hostsPageSize) : "";
  const currentScanner = me.preferences.defaultScannerAgentId ?? "";

  const [pageSize, setPageSize] = useState(currentPageSize);
  const [scanner, setScanner] = useState(currentScanner);
  const [banner, setBanner] = useState(me.preferences.showActiveScansBanner);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setPageSize(me.preferences.hostsPageSize ? String(me.preferences.hostsPageSize) : "");
    setScanner(me.preferences.defaultScannerAgentId ?? "");
    setBanner(me.preferences.showActiveScansBanner);
  }, [me.preferences.hostsPageSize, me.preferences.defaultScannerAgentId, me.preferences.showActiveScansBanner]);

  const dirty =
    pageSize !== currentPageSize || scanner !== currentScanner || banner !== me.preferences.showActiveScansBanner;

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const updated = await api.updatePreferences({
        hostsPageSize: pageSize ? Number(pageSize) : null,
        defaultScannerAgentId: scanner || null,
        showActiveScansBanner: banner,
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
      title="Dashboard"
      description="What the main host list shows you when you open it."
      error={error}
    >
      <form className="settings-form" onSubmit={save}>
        <label>
          Hosts per page
          <select value={pageSize} onChange={(e) => setPageSize(e.target.value)} disabled={busy}>
            <option value="">Default (50)</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </label>
        <label>
          Default scanner
          <select value={scanner} onChange={(e) => setScanner(e.target.value)} disabled={busy}>
            <option value="">All Scanner</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={banner} onChange={(e) => setBanner(e.target.checked)} disabled={busy} />
          Show the "Active scans" banner
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={busy || !dirty}>
            <IconSave /> {busy ? "Saving..." : "Save"}
          </button>
          <SaveState saved={saved} dirty={dirty} />
        </div>
      </form>
      <p className="host-meta">
        The default scanner is applied when you open the dashboard fresh - clearing the filter during a session
        stays cleared, rather than snapping back on every return from a host.
      </p>
    </SettingsCard>
  );
}
