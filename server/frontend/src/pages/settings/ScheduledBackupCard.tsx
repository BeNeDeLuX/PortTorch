import { FormEvent, useEffect, useState } from "react";
import { api, BackupSchedule, Me } from "../../api";
import { IconPlay, IconSave } from "../../components/icons";
import SettingsCard from "../../components/SettingsCard";
import { formatDateTime } from "../../lib/formatDate";

function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

// The archive Backup & Restore downloads, made every night and delivered
// somewhere that is not this host - a mounted share or an S3-compatible
// store. A backup that only lives on the machine it protects is lost with
// it.
export default function ScheduledBackupCard({ me }: { me: Me }) {
  const [schedule, setSchedule] = useState<BackupSchedule | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [hourUtc, setHourUtc] = useState("2");
  const [keep, setKeep] = useState("7");
  const [target, setTarget] = useState<"directory" | "s3">("directory");
  const [directory, setDirectory] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("porttorch/");
  const [accessKey, setAccessKey] = useState("");
  // Never prefilled - blank keeps the stored secret, like the SMTP password.
  const [secretKey, setSecretKey] = useState("");
  const [pathStyle, setPathStyle] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function fill(s: BackupSchedule) {
    setSchedule(s);
    setEnabled(s.enabled);
    setHourUtc(String(s.hourUtc));
    setKeep(String(s.keep));
    setTarget(s.target);
    setDirectory(s.directory ?? "");
    setEndpoint(s.s3.endpoint ?? "");
    setRegion(s.s3.region);
    setBucket(s.s3.bucket ?? "");
    setPrefix(s.s3.prefix);
    setAccessKey(s.s3.accessKey ?? "");
    setPathStyle(s.s3.pathStyle);
  }

  useEffect(() => {
    api
      .backupSchedule()
      .then(fill)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load the backup schedule"));
  }, []);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      fill(
        await api.updateBackupSchedule({
          enabled,
          hourUtc: parseInt(hourUtc, 10),
          keep: parseInt(keep, 10),
          target,
          directory: directory.trim() || null,
          s3: {
            endpoint: endpoint.trim() || null,
            region: region.trim() || "us-east-1",
            bucket: bucket.trim() || null,
            prefix: prefix.trim(),
            accessKey: accessKey.trim() || null,
            ...(secretKey ? { secretKey } : {}),
            pathStyle,
          },
        })
      );
      setSecretKey("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save the backup schedule");
    } finally {
      setSaving(false);
    }
  }

  async function handleRunNow() {
    setRunResult(null);
    setRunning(true);
    try {
      const r = await api.runBackupNow();
      fill(r.schedule);
      setRunResult(
        r.ok
          ? `Backup written to ${r.location} (${formatBytes(r.bytes ?? 0)})${r.pruned ? `, ${r.pruned} older removed` : ""}.`
          : `Failed: ${r.error}`
      );
    } catch (err) {
      setRunResult(err instanceof Error ? err.message : "Backup failed");
    } finally {
      setRunning(false);
    }
  }

  const last = schedule?.last;

  return (
    <SettingsCard
      title="Scheduled backups"
      description={
        <>
          Writes the same archive as the download above once a day and sends it off this host: to a directory inside the
          webserver container, typically an NFS or SMB share mounted on the host and passed in as a volume, or to an
          S3-compatible store (AWS, MinIO, Wasabi, Ceph). Only the newest archives are kept, and only files this schedule
          wrote are ever removed. A failed run raises the <code>backup.failed</code> alert. "Run now" uses the saved
          settings, so save first. Archives restore through the upload above or <code>scripts/restore.sh</code>.
        </>
      }
      error={error}
      notice={saved && <p className="callout-success">Backup schedule saved.</p>}
    >
      {last?.runAt && (
        <p className={last.status === "failed" ? "callout-warning" : "settings-state"}>
          Last run {formatDateTime(last.runAt, me.preferences)}:{" "}
          {last.status === "succeeded" ? (
            <>
              written to <code>{last.location}</code>
              {last.bytes !== null && ` (${formatBytes(last.bytes)})`}
            </>
          ) : (
            <>
              failed - {last.error}
              {last.successAt && <> Last successful backup: {formatDateTime(last.successAt, me.preferences)}.</>}
            </>
          )}
        </p>
      )}
      {schedule && (
        <form className="settings-form" onSubmit={handleSave}>
          <label className="hide-empty-toggle">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Back up every day
          </label>
          <label>
            At (UTC hour)
            <input className="input-number" type="number" min={0} max={23} value={hourUtc} onChange={(e) => setHourUtc(e.target.value)} />
          </label>
          <label>
            Keep the newest
            <input className="input-number" type="number" min={1} max={365} value={keep} onChange={(e) => setKeep(e.target.value)} />
          </label>
          <label>
            Destination
            <select value={target} onChange={(e) => setTarget(e.target.value as "directory" | "s3")}>
              <option value="directory">Directory (mounted share)</option>
              <option value="s3">S3-compatible storage</option>
            </select>
          </label>
          {target === "directory" ? (
            <label>
              Directory in the container
              <input placeholder="/backups" value={directory} onChange={(e) => setDirectory(e.target.value)} />
            </label>
          ) : (
            <>
              <label>
                Endpoint
                <input placeholder="https://s3.eu-central-1.amazonaws.com" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} />
              </label>
              <label>
                Region
                <input value={region} onChange={(e) => setRegion(e.target.value)} />
              </label>
              <label>
                Bucket
                <input value={bucket} onChange={(e) => setBucket(e.target.value)} />
              </label>
              <label>
                Prefix
                <input placeholder="porttorch/" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
              </label>
              <label>
                Access key
                <input autoComplete="off" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} />
              </label>
              <label>
                Secret key
                <input
                  type="password"
                  autoComplete="new-password"
                  placeholder={schedule.s3.secretKeySet ? "unchanged - type to replace" : "no secret stored"}
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                />
              </label>
              <label className="hide-empty-toggle">
                <input type="checkbox" checked={pathStyle} onChange={(e) => setPathStyle(e.target.checked)} />
                Path-style addresses (needed for MinIO and most self-hosted stores)
              </label>
            </>
          )}
          <div className="inline-actions settings-form-actions">
            <button type="submit" className="btn-icon-label" disabled={saving}>
              <IconSave /> {saving ? "Saving..." : "Save schedule"}
            </button>
            <button type="button" className="btn-icon-label" onClick={handleRunNow} disabled={running}>
              <IconPlay /> {running ? "Backing up..." : "Run now"}
            </button>
          </div>
        </form>
      )}
      {runResult && <p className="settings-state">{runResult}</p>}
    </SettingsCard>
  );
}
