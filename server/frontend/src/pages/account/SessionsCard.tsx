import { useState } from "react";
import { api } from "../../api";
import { IconLogOut } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";

export default function SessionsCard() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function revoke() {
    setResult(null);
    setBusy(true);
    try {
      const { revoked } = await api.revokeOtherSessions();
      setResult(revoked === 0 ? "No other sessions were signed in." : `Signed out ${revoked} other session(s).`);
    } catch (err) {
      setResult(err instanceof Error ? err.message : "Failed to sign out other sessions");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SettingsCard
      title="Sessions"
      description="Signs out every other browser or device currently signed in as you, keeping this one. Your password and 2FA are unchanged."
    >
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={revoke} disabled={busy}>
          <IconLogOut /> {busy ? "Signing out..." : "Sign out other sessions"}
        </button>
      </div>
      {result && <p className="host-meta">{result}</p>}
      <p className="host-meta">
        Use this when you have left a session open somewhere - changing your password to get the same effect is
        heavier and beside the point.
      </p>
    </SettingsCard>
  );
}
