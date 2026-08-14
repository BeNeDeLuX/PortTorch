import { FormEvent, useEffect, useState } from "react";
import { api, AppSettings, Me, TlsCertificateInfo } from "../api";
import { IconSave, IconUpload } from "../components/icons";
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

  useEffect(() => {
    load();
    api.appSettings().then(setAppSettings).catch(() => setAppSettings(null));
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
    </div>
  );
}
