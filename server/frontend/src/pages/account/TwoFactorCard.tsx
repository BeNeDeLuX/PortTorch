import { FormEvent, useEffect, useState } from "react";
import { TwoFactorSetup, api } from "../../api";
import { IconCheck, IconRefresh, IconX } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";

// Spans two grid columns: the setup step shows a QR code beside its
// instructions, and the enabled state carries two independent forms.
// Neither fits the single-column card the other account settings use.
export default function TwoFactorCard({ onMeRefresh }: { onMeRefresh: () => void }) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<TwoFactorSetup | null>(null);
  const [setupCode, setSetupCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [regenerateCode, setRegenerateCode] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .twoFactorStatus()
      .then((s) => setEnabled(s.enabled))
      .catch(() => setEnabled(false));
  }, []);

  async function startSetup() {
    setError(null);
    try {
      setSetup(await api.twoFactorSetup());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start 2FA setup");
    }
  }

  async function confirmSetup(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.twoFactorConfirm(setupCode.trim());
      setRecoveryCodes(result.recoveryCodes);
      setSetup(null);
      setSetupCode("");
      setEnabled(true);
      // Lifts the "you must set up 2FA" redirect immediately rather than
      // at the next sign-in.
      onMeRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    }
  }

  async function regenerate(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.regenerateRecoveryCodes(regenerateCode.trim());
      setRecoveryCodes(result.recoveryCodes);
      setRegenerateCode("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code");
    }
  }

  async function disable(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.twoFactorDisable(disablePassword);
      setDisablePassword("");
      setEnabled(false);
      setRecoveryCodes(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable 2FA");
    }
  }

  return (
    <SettingsCard
      title="Two-Factor Authentication"
      description="A code from an authenticator app on top of your password. Setting it up is yours alone to do - it needs your own device - so an administrator can only ever turn it off for you, never on."
      error={error}
      notice={
        recoveryCodes ? (
          <div className="callout">
            <strong>Save these recovery codes</strong> - each works once, and this is the only time they are shown.
            Use one to sign in if you lose access to your authenticator app.
            <pre className="key-reveal">{recoveryCodes.join("\n")}</pre>
            <button className="btn-icon-label" onClick={() => setRecoveryCodes(null)}>
              <IconCheck /> Got it
            </button>
          </div>
        ) : null
      }
    >
      {enabled === null ? (
        <p>Loading...</p>
      ) : enabled ? (
        <>
          <p className="callout-success">2FA is enabled on your account.</p>
          <h4>Regenerate recovery codes</h4>
          <p className="host-meta">Invalidates your existing recovery codes and issues a new set.</p>
          <form className="inline-form" onSubmit={regenerate}>
            <input
              placeholder="6-digit code"
              value={regenerateCode}
              onChange={(e) => setRegenerateCode(e.target.value)}
              inputMode="numeric"
            />
            <button type="submit" className="btn-icon-label" disabled={!regenerateCode.trim()}>
              <IconRefresh /> Regenerate
            </button>
          </form>

          <h4>Disable 2FA</h4>
          <p className="host-meta">
            Requires your password: a live session is not on its own proof that you are still the one at the
            keyboard, which is the case this defends against.
          </p>
          <form className="inline-form" onSubmit={disable}>
            <input
              type="password"
              placeholder="Current password"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
            />
            <button type="submit" className="btn-icon-label" disabled={!disablePassword}>
              <IconX /> Disable
            </button>
          </form>
        </>
      ) : setup ? (
        <form className="settings-form totp-setup" onSubmit={confirmSetup}>
          <p>Scan this with your authenticator app (Google Authenticator, 1Password, and so on):</p>
          <img src={setup.qrCodeDataUrl} alt="2FA setup QR code" width={200} height={200} />
          <p className="host-meta">
            Cannot scan it? Enter this secret manually: <code>{setup.secret}</code>
          </p>
          <label>
            Enter the 6-digit code to confirm
            <input value={setupCode} onChange={(e) => setSetupCode(e.target.value)} autoFocus inputMode="numeric" />
          </label>
          <div className="inline-actions settings-form-actions">
            <button type="submit" className="btn-icon-label" disabled={!setupCode.trim()}>
              <IconCheck /> Confirm
            </button>
            <button type="button" className="link-button btn-icon-label" onClick={() => setSetup(null)}>
              <IconX /> cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          <p className="host-meta">
            2FA is not enabled. Turning it on needs an authenticator app on your phone.
          </p>
          <div className="inline-actions">
            <button className="btn-icon-label" onClick={startSetup}>
              <IconCheck /> Enable 2FA
            </button>
          </div>
        </>
      )}
    </SettingsCard>
  );
}
