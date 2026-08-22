import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings, Me, TlsCertificateInfo } from "../api";
import { IconSave, IconSend, IconTrash, IconUpload } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";
import { certExpiryDaysLeft, certExpiryLabel, certExpiryStatus } from "../lib/certExpiry";

// Admin-only, like every other Admin-group page. Lets an admin replace
// the webserver's own TLS listener certificate (the one every browser/
// scanner connection negotiates against) with a real CA-issued one,
// instead of staying on the self-signed cert generateCert.ts creates on
// first boot. Not to be confused with the fleet-wide Certificates page,
// which shows certificates captured *from scanned hosts* - this is the
// one certificate for this webserver itself.
export default function Settings({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [info, setInfo] = useState<TlsCertificateInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [appSettings, setAppSettings] = useState<AppSettings | null>(null);
  const [savingAppSettings, setSavingAppSettings] = useState(false);
  const [appSettingsError, setAppSettingsError] = useState<string | null>(null);

  const [retentionDaysInput, setRetentionDaysInput] = useState("");
  const [savingRetention, setSavingRetention] = useState(false);
  const [retentionError, setRetentionError] = useState<string | null>(null);
  const [runningCleanup, setRunningCleanup] = useState(false);
  const [cleanupResult, setCleanupResult] = useState<string | null>(null);

  const [staleThresholdInput, setStaleThresholdInput] = useState("");
  const [savingStaleThreshold, setSavingStaleThreshold] = useState(false);
  const [staleThresholdError, setStaleThresholdError] = useState<string | null>(null);

  const [queueThresholdInput, setQueueThresholdInput] = useState("");
  const [savingQueueThreshold, setSavingQueueThreshold] = useState(false);
  const [queueThresholdError, setQueueThresholdError] = useState<string | null>(null);

  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpSecure, setSmtpSecure] = useState(false);
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpFrom, setSmtpFrom] = useState("");
  // Never prefilled - the API doesn't return the stored password. Blank
  // therefore means "keep whatever is stored", which is why the form
  // needs passwordSet from the server to say so honestly.
  const [smtpPassword, setSmtpPassword] = useState("");
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [smtpError, setSmtpError] = useState<string | null>(null);
  const [smtpSaved, setSmtpSaved] = useState(false);
  const [smtpTestTo, setSmtpTestTo] = useState("");
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState<string | null>(null);

  useEffect(() => {
    load();
    api
      .appSettings()
      .then((s) => {
        setAppSettings(s);
        setRetentionDaysInput(String(s.hostRetentionDays));
        setStaleThresholdInput(String(s.staleScanThresholdMinutes));
        setQueueThresholdInput(String(s.scanQueueWarningThreshold));
        setSmtpHost(s.smtp.host ?? "");
        setSmtpPort(String(s.smtp.port));
        setSmtpSecure(s.smtp.secure);
        setSmtpUser(s.smtp.user ?? "");
        setSmtpFrom(s.smtp.from ?? "");
      })
      .catch(() => setAppSettings(null));
  }, []);

  async function load() {
    setLoading(true);
    try {
      setInfo(await api.tlsCertificate());
    } finally {
      setLoading(false);
    }
  }

  async function handleToggleRequireAdminTotp() {
    if (!appSettings) return;
    setAppSettingsError(null);
    setSavingAppSettings(true);
    try {
      setAppSettings(await api.updateAppSettings({ requireAdminTotp: !appSettings.requireAdminTotp }));
    } catch (err) {
      setAppSettingsError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSavingAppSettings(false);
    }
  }

  async function handleSaveRetentionDays(e: FormEvent) {
    e.preventDefault();
    const days = parseInt(retentionDaysInput, 10);
    if (Number.isNaN(days) || days < 0) {
      setRetentionError("Enter a whole number of days, 0 or greater (0 disables the sweep).");
      return;
    }
    setRetentionError(null);
    setSavingRetention(true);
    try {
      const updated = await api.updateAppSettings({ hostRetentionDays: days });
      setAppSettings(updated);
      setRetentionDaysInput(String(updated.hostRetentionDays));
    } catch (err) {
      setRetentionError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSavingRetention(false);
    }
  }

  async function handleSaveStaleThreshold(e: FormEvent) {
    e.preventDefault();
    const minutes = parseInt(staleThresholdInput, 10);
    if (Number.isNaN(minutes) || minutes < 1) {
      setStaleThresholdError("Enter a whole number of minutes, 1 or greater.");
      return;
    }
    setStaleThresholdError(null);
    setSavingStaleThreshold(true);
    try {
      const updated = await api.updateAppSettings({ staleScanThresholdMinutes: minutes });
      setAppSettings(updated);
      setStaleThresholdInput(String(updated.staleScanThresholdMinutes));
    } catch (err) {
      setStaleThresholdError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSavingStaleThreshold(false);
    }
  }

  async function handleSaveSmtp(e: FormEvent) {
    e.preventDefault();
    const port = parseInt(smtpPort, 10);
    if (Number.isNaN(port) || port < 1 || port > 65535) {
      setSmtpError("Enter a valid port between 1 and 65535.");
      return;
    }
    setSmtpError(null);
    setSmtpSaved(false);
    setSavingSmtp(true);
    try {
      const updated = await api.updateAppSettings({
        smtp: {
          host: smtpHost.trim() || null,
          port,
          secure: smtpSecure,
          user: smtpUser.trim() || null,
          from: smtpFrom.trim() || null,
          // Omitted when left blank so saving an unrelated field can't
          // silently wipe working credentials; sent as null only when the
          // admin explicitly clears the username too, which is the one
          // case where keeping a password makes no sense.
          ...(smtpPassword ? { password: smtpPassword } : smtpUser.trim() ? {} : { password: null }),
        },
      });
      setAppSettings(updated);
      setSmtpPassword("");
      setSmtpSaved(true);
    } catch (err) {
      setSmtpError(err instanceof Error ? err.message : "Failed to save mail settings");
    } finally {
      setSavingSmtp(false);
    }
  }

  async function handleTestSmtp(e: FormEvent) {
    e.preventDefault();
    setSmtpTestResult(null);
    setTestingSmtp(true);
    try {
      const result = await api.testSmtp(smtpTestTo.trim());
      setSmtpTestResult(result.ok ? `Test email sent to ${smtpTestTo.trim()}.` : `Failed: ${result.error}`);
    } catch (err) {
      setSmtpTestResult(err instanceof Error ? err.message : "Test failed");
    } finally {
      setTestingSmtp(false);
    }
  }

  async function handleSaveQueueThreshold(e: FormEvent) {
    e.preventDefault();
    const count = parseInt(queueThresholdInput, 10);
    if (Number.isNaN(count) || count < 1) {
      setQueueThresholdError("Enter a whole number of pending requests, 1 or greater.");
      return;
    }
    setQueueThresholdError(null);
    setSavingQueueThreshold(true);
    try {
      const updated = await api.updateAppSettings({ scanQueueWarningThreshold: count });
      setAppSettings(updated);
      setQueueThresholdInput(String(updated.scanQueueWarningThreshold));
    } catch (err) {
      setQueueThresholdError(err instanceof Error ? err.message : "Failed to update setting");
    } finally {
      setSavingQueueThreshold(false);
    }
  }

  async function handleCleanupNow() {
    if (
      !window.confirm(
        `Permanently delete every host not seen in the last ${appSettings?.hostRetentionDays ?? "?"} day(s) (along with all their ports/screenshots/tags/comments/certificates), and every audit log entry older than the same window? This runs the same purge the hourly sweep does, right now, and can't be undone.`
      )
    ) {
      return;
    }
    setRetentionError(null);
    setCleanupResult(null);
    setRunningCleanup(true);
    try {
      const result = await api.runRetentionSweepNow();
      const parts: string[] = [];
      parts.push(result.purgedHosts === 0 ? "no hosts" : `${result.purgedHosts} host(s)`);
      parts.push(result.purgedAuditLogEntries === 0 ? "no audit log entries" : `${result.purgedAuditLogEntries} audit log entry/entries`);
      setCleanupResult(`Purged ${parts.join(" and ")}.`);
    } catch (err) {
      setRetentionError(err instanceof Error ? err.message : "Failed to run cleanup");
    } finally {
      setRunningCleanup(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!certFile || !keyFile) return;
    setError(null);
    setSuccess(null);
    setUploading(true);
    try {
      const updated = await api.uploadTlsCertificate(certFile, keyFile);
      setInfo(updated);
      setCertFile(null);
      setKeyFile(null);
      setSuccess("Certificate updated and applied immediately - new connections now use it.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload certificate");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Settings</h2>

      <h3>TLS Certificate</h3>
      <p className="host-meta">
        The certificate this webserver presents to browsers and scanners. By default it's a self-signed one,
        auto-generated on first boot. Uploading a real, CA-issued certificate here applies it immediately - no
        restart needed - and the previous certificate is kept as a timestamped backup on disk.
      </p>

      {loading ? (
        <p>Loading...</p>
      ) : info ? (
        <div className="callout">
          <table>
            <tbody>
              <tr>
                <th>Subject</th>
                <td>
                  {info.subjectCN ?? "-"}
                  {info.selfSigned && <span className="chip-inline">self-signed</span>}
                </td>
              </tr>
              <tr>
                <th>Issuer</th>
                <td>{info.issuerCN ?? "-"}</td>
              </tr>
              <tr>
                <th>Valid from</th>
                <td>{formatDateTime(info.validFrom, me.preferences)}</td>
              </tr>
              <tr>
                <th>Valid to</th>
                <td>
                  {formatDateTime(info.validTo, me.preferences)}{" "}
                  <span className={`expiry-label expiry-${certExpiryStatus(info.validTo)}`}>
                    {certExpiryLabel(info.validTo)}
                    {(() => {
                      const days = certExpiryDaysLeft(info.validTo);
                      if (days === null) return null;
                      return days >= 0 ? ` (${days}d left)` : ` (${-days}d ago)`;
                    })()}
                  </span>
                </td>
              </tr>
              <tr>
                <th>Fingerprint (SHA-256)</th>
                <td className="banner">{info.fingerprint256}</td>
              </tr>
            </tbody>
          </table>
        </div>
      ) : (
        <p className="error">Could not load the current certificate.</p>
      )}

      {error && <p className="error">{error}</p>}
      {success && <p className="host-meta">{success}</p>}

      <form className="schedule-form" onSubmit={handleSubmit}>
        <label>
          Certificate (PEM, full chain)
          <input
            type="file"
            accept=".pem,.crt,.cer,text/plain"
            onChange={(e) => setCertFile(e.target.files?.[0] ?? null)}
          />
        </label>
        <label>
          Private key (PEM)
          <input type="file" accept=".pem,.key,text/plain" onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)} />
        </label>
        <button type="submit" className="btn-icon-label" disabled={!certFile || !keyFile || uploading}>
          <IconUpload /> {uploading ? "Uploading..." : "Upload & apply"}
        </button>
      </form>

      <h3>Security</h3>
      <p className="host-meta">
        Two-factor authentication is otherwise self-service and optional (see the Account page). Turning this on
        redirects any admin account without 2FA enabled to the Account page until they set it up - it doesn't touch
        operator or user accounts, and any admin can turn it back off again.
      </p>

      {appSettingsError && <p className="error">{appSettingsError}</p>}

      {appSettings && (
        <p>
          Require 2FA for all admin accounts:{" "}
          <strong>{appSettings.requireAdminTotp ? "on" : "off"}</strong>{" "}
          <button className="btn-icon-label" onClick={handleToggleRequireAdminTotp} disabled={savingAppSettings}>
            <IconSave /> {appSettings.requireAdminTotp ? "Turn off" : "Turn on"}
          </button>
        </p>
      )}

      <h3>Host Retention</h3>
      <p className="host-meta">
        Hosts not seen (last seen) in this many days are purged automatically every hour, along with all their
        history - ports, screenshots, tags, comments, certificates. Audit log entries older than the same window are
        purged too, in the same sweep. Set to 0 to disable the sweep entirely.
      </p>

      {retentionError && <p className="error">{retentionError}</p>}
      {cleanupResult && <p className="host-meta">{cleanupResult}</p>}

      {appSettings && (
        <>
          <form className="inline-form" onSubmit={handleSaveRetentionDays}>
            <input
              type="number"
              min={0}
              step={1}
              value={retentionDaysInput}
              onChange={(e) => setRetentionDaysInput(e.target.value)}
              aria-label="Host retention days"
            />
            <span className="host-meta">days</span>
            <button type="submit" className="btn-icon-label" disabled={savingRetention}>
              <IconSave /> Save
            </button>
          </form>
          <p>
            <button className="btn-icon-label" onClick={handleCleanupNow} disabled={runningCleanup}>
              <IconTrash /> {runningCleanup ? "Cleaning up..." : "Clean up now"}
            </button>
          </p>
        </>
      )}

      <h3>Scan Staleness</h3>
      <p className="host-meta">
        A running scan flagged "stale" (Active scans banner, Scanner Agents page, host detail's last rescan line)
        usually means the scanner that owns it is offline or died mid-scan - but a scan that's simply slow (e.g. a
        large target range's masscan pass, which reports nothing until it fully completes) won't trip this as long
        as the scanner keeps sending its periodic progress heartbeat; only a scan with no such heartbeat for this
        many minutes is flagged. Purely a display/alert hint - nothing is deleted or reassigned.
      </p>

      {staleThresholdError && <p className="error">{staleThresholdError}</p>}

      {appSettings && (
        <form className="inline-form" onSubmit={handleSaveStaleThreshold}>
          <input
            type="number"
            min={1}
            step={1}
            value={staleThresholdInput}
            onChange={(e) => setStaleThresholdInput(e.target.value)}
            aria-label="Stale scan threshold minutes"
          />
          <span className="host-meta">minutes</span>
          <button type="submit" className="btn-icon-label" disabled={savingStaleThreshold}>
            <IconSave /> Save
          </button>
        </form>
      )}

      <h3>Scan Queue Warning</h3>
      <p className="host-meta">
        Fleet Health's "Scan Queue" card (agents/queued requests still waiting to be claimed) warns once this many
        requests are pending at once. A handful of queued requests is often normal during a busy period - raise this
        if that's the case for your fleet. A single request stuck pending for 30+ minutes still escalates straight to
        critical regardless of this setting, since that specifically suggests a scanner has stopped polling.
      </p>

      {queueThresholdError && <p className="error">{queueThresholdError}</p>}

      {appSettings && (
        <form className="inline-form" onSubmit={handleSaveQueueThreshold}>
          <input
            type="number"
            min={1}
            step={1}
            value={queueThresholdInput}
            onChange={(e) => setQueueThresholdInput(e.target.value)}
            aria-label="Scan queue warning threshold"
          />
          <span className="host-meta">pending requests</span>
          <button type="submit" className="btn-icon-label" disabled={savingQueueThreshold}>
            <IconSave /> Save
          </button>
        </form>
      )}

      <h3>Mail Server (SMTP)</h3>
      <p className="host-meta">
        Used by "email" alert channels on the Webhooks page and by the daily digest email. Leave the host blank if you
        only use webhook channels - nothing here is required otherwise. These settings used to live in the .env file
        and needed a redeploy to change; editing those variables now has no effect.
      </p>

      {smtpError && <p className="error">{smtpError}</p>}
      {smtpSaved && <p className="callout-success">Mail settings saved.</p>}

      {appSettings && (
        <>
          <form className="settings-form" onSubmit={handleSaveSmtp}>
            <label>
              Host
              <input
                placeholder="smtp.example.com"
                value={smtpHost}
                onChange={(e) => setSmtpHost(e.target.value)}
              />
            </label>
            <label>
              Port
              <input
                type="number"
                min={1}
                max={65535}
                step={1}
                value={smtpPort}
                onChange={(e) => setSmtpPort(e.target.value)}
              />
            </label>
            <label className="hide-empty-toggle">
              <input type="checkbox" checked={smtpSecure} onChange={(e) => setSmtpSecure(e.target.checked)} />
              Implicit TLS (port 465). Leave off for STARTTLS on 587.
            </label>
            <label>
              Username
              <input
                autoComplete="off"
                placeholder="optional - leave blank for an unauthenticated relay"
                value={smtpUser}
                onChange={(e) => setSmtpUser(e.target.value)}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete="new-password"
                placeholder={appSettings.smtp.passwordSet ? "unchanged - type to replace" : "no password stored"}
                value={smtpPassword}
                onChange={(e) => setSmtpPassword(e.target.value)}
              />
            </label>
            <label>
              Sender address
              <input
                placeholder="porttorch@example.com - defaults to the username"
                value={smtpFrom}
                onChange={(e) => setSmtpFrom(e.target.value)}
              />
            </label>
            <button type="submit" className="btn-icon-label" disabled={savingSmtp}>
              <IconSave /> Save mail settings
            </button>
          </form>

          <p className="host-meta">
            Sends a real message using the <em>saved</em> settings - save first, then test. A connection check alone
            wouldn't catch the failures that actually bite here, like a sender address the server refuses to relay for.
          </p>
          <form className="inline-form" onSubmit={handleTestSmtp}>
            <input
              type="email"
              placeholder="Send a test email to..."
              value={smtpTestTo}
              onChange={(e) => setSmtpTestTo(e.target.value)}
            />
            <button type="submit" className="btn-icon-label" disabled={testingSmtp || !smtpTestTo.trim()}>
              <IconSend /> Send test
            </button>
          </form>
          {smtpTestResult && <p className="host-meta">{smtpTestResult}</p>}
        </>
      )}
    </div>
  );
}
