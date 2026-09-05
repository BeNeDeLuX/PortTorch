import { useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave } from "../../components/icons";
import SettingsCard from "./SettingsCard";

export default function RequireTotpCard({
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
      onUpdated(await api.updateAppSettings({ requireAdminTotp: !settings.requireAdminTotp }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SettingsCard
      title="Require 2FA for admins"
      description={
        <>
          Two-factor authentication is otherwise self-service and optional (see the Account page). Turning this on
          redirects any admin without 2FA to the Account page until they set it up. It doesn't touch operator or user
          accounts, and any admin can turn it back off.
        </>
      }
      error={error}
    >
      <p className="settings-state">
        Currently <strong>{settings.requireAdminTotp ? "required" : "optional"}</strong>
      </p>
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={handleToggle} disabled={saving}>
          <IconSave /> {settings.requireAdminTotp ? "Turn off" : "Turn on"}
        </button>
      </div>
    </SettingsCard>
  );
}
