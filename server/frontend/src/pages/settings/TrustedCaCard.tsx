import { FormEvent, useEffect, useState } from "react";
import { api, Me, TrustedCaCertificate } from "../../api";
import { IconTrash, IconUpload } from "../../components/icons";
import { formatDateTime } from "../../lib/formatDate";
import SettingsCard from "./SettingsCard";

export default function TrustedCaCard({ me }: { me: Me }) {
  const [certs, setCerts] = useState<TrustedCaCertificate[]>([]);
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      setCerts(await api.caCertificates());
    } catch {
      setCerts([]);
    }
  }

  async function handleUpload(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !pem.trim()) return;
    setError(null);
    setBusy(true);
    try {
      await api.uploadCaCertificate(name.trim(), pem);
      setName("");
      setPem("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add this certificate.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(cert: TrustedCaCertificate) {
    if (!window.confirm(`Stop trusting "${cert.name}"? Connections that relied on it will fail verification again.`)) {
      return;
    }
    await api.deleteCaCertificate(cert.id);
    await load();
  }

  return (
    <SettingsCard
      title="Trusted CA Certificates"
      description={
        <>
          Authorities this webserver trusts when it connects <em>out</em> - to the mail relay and the SIEM collector.
          Uploading the CA that signed an internal server's certificate lets verification succeed without switching it
          off, which is the better answer: off accepts any certificate, including a swapped-in one. Your uploads are
          added to the public root store, not put in its place. Nothing here affects the listener certificate above.
        </>
      }
      error={error}
    >
      {certs.length === 0 ? (
        <p className="settings-state">Only the public root store is trusted.</p>
      ) : (
        <ul className="settings-list">
          {certs.map((c) => (
            <li key={c.id}>
              <span className="settings-list-main">
                {c.name}
                {c.not_after && new Date(c.not_after).getTime() < Date.now() && (
                  <span className="expiry-label expiry-expired"> expired</span>
                )}
              </span>
              <span className="empty">
                {c.not_after ? `until ${formatDateTime(c.not_after, me.preferences)}` : "no expiry"}
              </span>
              <button type="button" className="link-button btn-icon-label" onClick={() => handleDelete(c)}>
                <IconTrash size={12} /> Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      <form className="settings-form" onSubmit={handleUpload}>
        <label>
          Name
          <input placeholder="e.g. Corp Root CA" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Certificate (PEM)
          <textarea
            className="ca-pem-input"
            placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
            value={pem}
            onChange={(e) => setPem(e.target.value)}
          />
        </label>
        <div className="inline-actions">
          <button type="submit" className="btn-icon-label" disabled={busy}>
            <IconUpload /> {busy ? "Adding..." : "Add certificate"}
          </button>
        </div>
      </form>
    </SettingsCard>
  );
}
