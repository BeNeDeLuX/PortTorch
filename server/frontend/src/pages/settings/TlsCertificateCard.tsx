import { FormEvent, useEffect, useState } from "react";
import { api, Me, TlsCertificateInfo } from "../../api";
import { IconUpload } from "../../components/icons";
import { certExpiryDaysLeft, certExpiryLabel, certExpiryStatus } from "../../lib/certExpiry";
import { formatDateTime } from "../../lib/formatDate";
import SettingsCard from "./SettingsCard";

// Not to be confused with the fleet-wide Certificates page, which shows
// certificates captured *from scanned hosts* - this is the one
// certificate this webserver itself presents.
export default function TlsCertificateCard({ me }: { me: Me }) {
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
    <SettingsCard
      title="TLS Certificate"
      description={
        <>
          What this webserver presents to browsers and scanners. By default it's self-signed, generated on first boot.
          Uploading a CA-issued certificate applies it immediately - no restart - and the previous one is kept as a
          timestamped backup on disk.
        </>
      }
      error={error}
      notice={success && <p className="callout-success">{success}</p>}
    >
      {loading ? (
        <p className="empty">Loading...</p>
      ) : info ? (
        <dl className="settings-facts">
          <dt>Subject</dt>
          <dd>
            {info.subjectCN ?? "-"}
            {info.selfSigned && <span className="chip-inline">self-signed</span>}
          </dd>
          <dt>Issuer</dt>
          <dd>{info.issuerCN ?? "-"}</dd>
          <dt>Valid to</dt>
          <dd>
            {formatDateTime(info.validTo, me.preferences)}{" "}
            <span className={`expiry-label expiry-${certExpiryStatus(info.validTo)}`}>
              {certExpiryLabel(info.validTo)}
              {(() => {
                const days = certExpiryDaysLeft(info.validTo);
                if (days === null) return null;
                return days >= 0 ? ` (${days}d left)` : ` (${-days}d ago)`;
              })()}
            </span>
          </dd>
          <dt>Fingerprint</dt>
          <dd className="fingerprint-cell">{info.fingerprint256}</dd>
        </dl>
      ) : (
        <p className="error">Could not load the current certificate.</p>
      )}

      <form className="settings-form" onSubmit={handleSubmit}>
        <label>
          Certificate (PEM, full chain)
          <input type="file" accept=".pem,.crt,.cer,text/plain" onChange={(e) => setCertFile(e.target.files?.[0] ?? null)} />
        </label>
        <label>
          Private key (PEM)
          <input type="file" accept=".pem,.key,text/plain" onChange={(e) => setKeyFile(e.target.files?.[0] ?? null)} />
        </label>
        <div className="inline-actions">
          <button type="submit" className="btn-icon-label" disabled={!certFile || !keyFile || uploading}>
            <IconUpload /> {uploading ? "Uploading..." : "Upload & apply"}
          </button>
        </div>
      </form>
    </SettingsCard>
  );
}
