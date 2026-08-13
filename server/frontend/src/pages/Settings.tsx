import { FormEvent, useEffect, useState } from "react";
import { api, Me, TlsCertificateInfo } from "../api";
import { IconUpload } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { formatDateTime } from "../lib/formatDate";

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

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      setInfo(await api.tlsCertificate());
    } finally {
      setLoading(false);
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
                  {info.expired && <span className="update-failed-badge">expired</span>}
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
                <td>{formatDateTime(info.validTo, me.preferences)}</td>
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
    </div>
  );
}
