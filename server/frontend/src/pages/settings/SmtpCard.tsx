import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings } from "../../api";
import { IconSave, IconSend } from "../../components/icons";
import SettingsCard from "./SettingsCard";

export default function SmtpCard({
  settings,
  onUpdated,
}: {
  settings: AppSettings;
  onUpdated: (s: AppSettings) => void;
}) {
  const [host, setHost] = useState(settings.smtp.host ?? "");
  const [port, setPort] = useState(String(settings.smtp.port));
  const [secure, setSecure] = useState(settings.smtp.secure);
  const [user, setUser] = useState(settings.smtp.user ?? "");
  const [from, setFrom] = useState(settings.smtp.from ?? "");
  const [verifyTls, setVerifyTls] = useState(settings.smtp.verifyTls);
  // Never prefilled - the API doesn't return the stored password. Blank
  // therefore means "keep whatever is stored", which is why the form
  // needs passwordSet from the server to say so honestly.
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testTo, setTestTo] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    setHost(settings.smtp.host ?? "");
    setPort(String(settings.smtp.port));
    setSecure(settings.smtp.secure);
    setUser(settings.smtp.user ?? "");
    setFrom(settings.smtp.from ?? "");
    setVerifyTls(settings.smtp.verifyTls);
  }, [settings.smtp]);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    const portValue = parseInt(port, 10);
    if (Number.isNaN(portValue) || portValue < 1 || portValue > 65535) {
      setError("Enter a valid port between 1 and 65535.");
      return;
    }
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      onUpdated(
        await api.updateAppSettings({
          smtp: {
            host: host.trim() || null,
            port: portValue,
            secure,
            user: user.trim() || null,
            from: from.trim() || null,
            verifyTls,
            // Omitted when left blank so saving an unrelated field can't
            // silently wipe working credentials; sent as null only when
            // the admin explicitly clears the username too, which is the
            // one case where keeping a password makes no sense.
            ...(password ? { password } : user.trim() ? {} : { password: null }),
          },
        })
      );
      setPassword("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save mail settings");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(e: FormEvent) {
    e.preventDefault();
    setTestResult(null);
    setTesting(true);
    try {
      const result = await api.testSmtp(testTo.trim());
      setTestResult(result.ok ? `Test email sent to ${testTo.trim()}.` : `Failed: ${result.error}`);
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : "Test failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <SettingsCard
      title="Mail Server (SMTP)"
      description={
        <>
          Used by email alert channels and the daily digest. Leave the host blank if you only use webhook channels -
          nothing here is required otherwise. The test sends a real message using the <em>saved</em> settings, so save
          first: a connection check alone wouldn't catch the failures that actually bite, like a sender address the
          server refuses to relay for.
        </>
      }
      error={error}
      notice={saved && <p className="callout-success">Mail settings saved.</p>}
    >
      <form className="settings-form" onSubmit={handleSave}>
        <label>
          Host
          <input placeholder="smtp.example.com" value={host} onChange={(e) => setHost(e.target.value)} />
        </label>
        <label>
          Port
          <input className="input-number" type="number" min={1} max={65535} step={1} value={port} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label>
          Username
          <input
            autoComplete="off"
            placeholder="optional - blank for an unauthenticated relay"
            value={user}
            onChange={(e) => setUser(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="new-password"
            placeholder={settings.smtp.passwordSet ? "unchanged - type to replace" : "no password stored"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <label>
          Sender address
          <input
            placeholder="porttorch@example.com - defaults to the username"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={secure} onChange={(e) => setSecure(e.target.checked)} />
          Implicit TLS (port 465). Leave off for STARTTLS on 587.
        </label>
        <label className="hide-empty-toggle">
          <input type="checkbox" checked={verifyTls} onChange={(e) => setVerifyTls(e.target.checked)} />
          Verify the mail server's TLS certificate. Turn off for an internal relay with a self-signed or private-CA
          certificate - that is what "self-signed certificate in certificate chain" means.
        </label>
        <div className="inline-actions settings-form-actions">
          <button type="submit" className="btn-icon-label" disabled={saving}>
            <IconSave /> {saving ? "Saving..." : "Save mail settings"}
          </button>
        </div>
      </form>

      <form className="inline-form settings-test-row" onSubmit={handleTest}>
        <input type="email" placeholder="Send a test email to..." value={testTo} onChange={(e) => setTestTo(e.target.value)} />
        <button type="submit" className="btn-icon-label" disabled={testing || !testTo.trim()}>
          <IconSend /> {testing ? "Sending..." : "Send test"}
        </button>
      </form>
      {testResult && <p className="settings-state">{testResult}</p>}
    </SettingsCard>
  );
}
