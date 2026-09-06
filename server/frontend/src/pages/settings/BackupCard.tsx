import { useEffect, useState } from "react";
import { api, BackupEstimate, RestoreResult } from "../../api";
import { IconDownload, IconUpload, IconWarning } from "../../components/icons";
import { formatBytes } from "../../lib/formatBytes";
import SettingsCard from "./SettingsCard";

// The word the operator has to type to confirm a restore. The same one
// scripts/restore.sh asks for, so the two paths ask the same question.
const CONFIRM_WORD = "restore";

export default function BackupCard() {
  const [estimate, setEstimate] = useState<BackupEstimate | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [preparing, setPreparing] = useState(false);

  const [file, setFile] = useState<File | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [restored, setRestored] = useState<RestoreResult | null>(null);
  const [backOnline, setBackOnline] = useState(false);

  useEffect(() => {
    api.backupEstimate().then(setEstimate).catch(() => setEstimate(null));
  }, []);

  // The download is a plain navigation, so a failure would otherwise land
  // as a raw JSON page in the browser. Asking for the estimate first
  // catches the one failure that actually happens - no room to stage the
  // archive - and reports it here instead.
  async function download() {
    setDownloadError(null);
    setPreparing(true);
    try {
      const fresh = await api.backupEstimate();
      setEstimate(fresh);
      if (!fresh.enoughSpace) {
        setDownloadError(
          `Not enough free disk space to stage the archive: ${formatBytes(fresh.freeBytes)} free, about ` +
            `${formatBytes(fresh.requiredBytes)} needed.`
        );
        return;
      }
      window.location.href = api.backupDownloadUrl;
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Could not prepare the backup.");
    } finally {
      setPreparing(false);
    }
  }

  async function restore() {
    if (!file || confirmText !== CONFIRM_WORD) return;
    setRestoreError(null);
    setRestoring(true);
    try {
      const result = await api.restoreBackup(file);
      setRestored(result);
      waitForRestart();
    } catch (err) {
      setRestoreError(err instanceof Error ? err.message : "The restore failed.");
      setRestoring(false);
    }
  }

  // The webserver exits on purpose once a restore lands, so the container
  // comes back with migrations re-run against the restored schema and no
  // stale caches. Poll until it answers again rather than leaving the
  // page sitting on a dead connection - /healthz needs no session, which
  // matters here because the restore replaced the session table too.
  function waitForRestart() {
    const started = Date.now();
    const tick = async () => {
      try {
        const res = await fetch("/healthz", { cache: "no-store" });
        if (res.ok) {
          setBackOnline(true);
          return;
        }
      } catch {
        // Still down - expected for the first few seconds.
      }
      if (Date.now() - started < 120_000) setTimeout(tick, 2000);
    };
    setTimeout(tick, 3000);
  }

  if (restored) {
    return (
      <SettingsCard
        title="Backup & Restore"
        description="The backup has been restored."
      >
        <div className="callout-success">
          Restored the backup from {restored.manifest.created_at ?? "an unknown date"} ({restored.screenshotsRestored}{" "}
          screenshot file{restored.screenshotsRestored === 1 ? "" : "s"}).
        </div>
        {restored.warning && (
          <div className="callout-warning">
            <IconWarning /> {restored.warning}
          </div>
        )}
        <p className="host-meta">
          {backOnline
            ? "The webserver has restarted and is back up. Accounts and sign-ins came from the backup too, so if your own session was not in it you will be asked to sign in again - with the password that account had when the backup was taken. The one exception is the admin account named by ADMIN_USERNAME, whose password the restart re-applies from .env."
            : "The webserver is restarting so it picks up the restored database cleanly. This usually takes a few seconds."}
        </p>
        <div className="inline-actions">
          <button className="btn-icon-label" disabled={!backOnline} onClick={() => window.location.reload()}>
            {backOnline ? "Reload the dashboard" : "Waiting for the webserver..."}
          </button>
        </div>
      </SettingsCard>
    );
  }

  return (
    <SettingsCard
      title="Backup & Restore"
      description={
        <>
          A full backup of everything that cannot be rebuilt from the image: the database and the screenshot and
          certificate volumes. The archive is the same format <code>scripts/backup.sh</code> writes, so one taken here
          can be restored on the host with <code>scripts/restore.sh</code>, and one taken by the nightly timer can be
          uploaded below.
        </>
      }
      error={downloadError ?? restoreError}
    >
      <h4>Create a backup</h4>
      {estimate && (
        <p className="host-meta">
          Database {formatBytes(estimate.databaseBytes)}, screenshots {formatBytes(estimate.screenshotBytes)},
          certificates {formatBytes(estimate.certBytes)}. The archive is compressed, so it comes out smaller than the{" "}
          {formatBytes(estimate.totalBytes)} total.
        </p>
      )}
      <p className="host-meta">
        The archive contains every password hash and the webserver's TLS private key. Store it accordingly.
      </p>
      <div className="inline-actions">
        <button className="btn-icon-label" onClick={download} disabled={preparing}>
          <IconDownload /> {preparing ? "Preparing..." : "Create and download backup"}
        </button>
      </div>

      <h4>Restore a backup</h4>
      <div className="callout-danger">
        <IconWarning /> This replaces the entire database and every screenshot with the archive's contents. Anything
        recorded since that backup was taken is lost, and it cannot be undone. Accounts go with it: the users,
        passwords and signed-in sessions that apply afterwards are the ones the backup holds, so you may be signed out
        and need the password that account had back then. The exception is the admin account named by{" "}
        <code>ADMIN_USERNAME</code> - the restart re-seeds it from <code>ADMIN_PASSWORD</code> in <code>.env</code>,
        which is also how you get back in if the backup's own admin password is lost.
      </div>
      <p className="host-meta">
        The TLS certificate in the archive is deliberately <strong>not</strong> restored: it identifies this deployment,
        and installing one issued for a different host would break the connection you would need to put it right. Use{" "}
        <code>scripts/restore.sh</code> on the host if you do want the certificate back too. The webserver restarts
        itself when the restore finishes.
      </p>

      <div className="settings-form">
        <label className="settings-field-wide">
          Backup archive
          <input
            type="file"
            accept=".gz,.tgz,application/gzip,application/x-gzip"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setRestoreError(null);
            }}
          />
        </label>
        <label>
          {/* One span, not three loose children: .settings-form label is
              a column flex container, so a bare <code> between two text
              nodes becomes its own row and the prompt reads as three
              stacked lines. */}
          <span>
            Type <code>{CONFIRM_WORD}</code> to confirm
          </span>
          <input
            type="text"
            value={confirmText}
            autoComplete="off"
            placeholder={CONFIRM_WORD}
            onChange={(e) => setConfirmText(e.target.value)}
          />
        </label>
        <div className="inline-actions settings-form-actions">
          <button
            className="btn-icon-label"
            onClick={restore}
            disabled={!file || confirmText !== CONFIRM_WORD || restoring}
          >
            <IconUpload /> {restoring ? "Restoring..." : "Restore this backup"}
          </button>
        </div>
      </div>
    </SettingsCard>
  );
}
