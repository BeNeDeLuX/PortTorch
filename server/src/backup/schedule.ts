import fs from "fs";
import path from "path";
import { recordAudit } from "../audit/log";
import { db } from "../db";
import { toDateOnlyString } from "../lib/dateOnly";
import { logger } from "../logger";
import { caBundle } from "../settings/caCertificates";
import { dispatchWebhook } from "../webhooks/dispatch";
import { BackupSpaceError, createBackupArchive } from "./archive";
import { deleteObject, listObjects, putObjectFromFile, type S3Config } from "./s3";

const CHECK_INTERVAL_MS = 5 * 60 * 1000;
// Only files this feature wrote are ever pruned - the name createBackupArchive
// gives them. Anything else in the directory or under the prefix is left
// alone, so pointing it at a shared location cannot delete someone else's
// files.
const ARCHIVE_NAME = /^porttorch-\d{8}-\d{6}Z\.tar\.gz$/;

export interface BackupScheduleSettings {
  enabled: boolean;
  hourUtc: number;
  keep: number;
  target: "directory" | "s3";
  directory: string | null;
  s3: {
    endpoint: string | null;
    region: string;
    bucket: string | null;
    prefix: string;
    accessKey: string | null;
    secretKey: string | null;
    pathStyle: boolean;
  };
  last: {
    runAt: Date | null;
    status: "succeeded" | "failed" | null;
    error: string | null;
    location: string | null;
    bytes: number | null;
    successAt: Date | null;
  };
}

export type BackupScheduleInput = Omit<BackupScheduleSettings, "last" | "s3"> & {
  // Omitted keeps the stored secret, like the SMTP password.
  s3: Omit<BackupScheduleSettings["s3"], "secretKey"> & { secretKey?: string | null };
};

export async function getBackupSchedule(): Promise<BackupScheduleSettings> {
  const r = await db
    .selectFrom("app_settings")
    .select([
      "backup_schedule_enabled",
      "backup_hour_utc",
      "backup_keep",
      "backup_target",
      "backup_directory",
      "backup_s3_endpoint",
      "backup_s3_region",
      "backup_s3_bucket",
      "backup_s3_prefix",
      "backup_s3_access_key",
      "backup_s3_secret_key",
      "backup_s3_path_style",
      "backup_last_run_at",
      "backup_last_status",
      "backup_last_error",
      "backup_last_location",
      "backup_last_bytes",
      "backup_last_success_at",
    ])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  return {
    enabled: r.backup_schedule_enabled,
    hourUtc: r.backup_hour_utc,
    keep: r.backup_keep,
    target: r.backup_target,
    directory: r.backup_directory,
    s3: {
      endpoint: r.backup_s3_endpoint,
      region: r.backup_s3_region,
      bucket: r.backup_s3_bucket,
      prefix: r.backup_s3_prefix,
      accessKey: r.backup_s3_access_key,
      secretKey: r.backup_s3_secret_key,
      pathStyle: r.backup_s3_path_style,
    },
    last: {
      runAt: r.backup_last_run_at,
      status: r.backup_last_status,
      error: r.backup_last_error,
      location: r.backup_last_location,
      // bigint - converted, see server/CLAUDE.md's Scan History notes.
      bytes: r.backup_last_bytes === null ? null : Number(r.backup_last_bytes),
      successAt: r.backup_last_success_at,
    },
  };
}

export async function setBackupSchedule(input: BackupScheduleInput): Promise<void> {
  await db
    .updateTable("app_settings")
    .set({
      backup_schedule_enabled: input.enabled,
      backup_hour_utc: input.hourUtc,
      backup_keep: input.keep,
      backup_target: input.target,
      backup_directory: input.directory,
      backup_s3_endpoint: input.s3.endpoint,
      backup_s3_region: input.s3.region,
      backup_s3_bucket: input.s3.bucket,
      backup_s3_prefix: input.s3.prefix,
      backup_s3_access_key: input.s3.accessKey,
      backup_s3_path_style: input.s3.pathStyle,
      ...(input.s3.secretKey === undefined ? {} : { backup_s3_secret_key: input.s3.secretKey }),
    })
    .where("id", "=", 1)
    .execute();
}

// What is still missing before a run can succeed, for the save check and
// the page.
export function missingBackupSettings(s: Pick<BackupScheduleSettings, "target" | "directory" | "s3">): string[] {
  if (s.target === "directory") return s.directory ? [] : ["directory"];
  const missing: string[] = [];
  if (!s.s3.endpoint) missing.push("endpoint");
  if (!s.s3.bucket) missing.push("bucket");
  if (!s.s3.accessKey) missing.push("access key");
  if (!s.s3.secretKey) missing.push("secret key");
  return missing;
}

// Keeps the newest `keep` archives this feature wrote. Names sort by time,
// so the oldest are simply the first ones.
export function archivesToPrune(names: string[], keep: number): string[] {
  const ours = names.filter((n) => ARCHIVE_NAME.test(path.basename(n))).sort((a, b) => path.basename(a).localeCompare(path.basename(b)));
  return ours.slice(0, Math.max(0, ours.length - keep));
}

async function deliverToDirectory(dir: string, archive: { path: string; filename: string }, keep: number): Promise<{ location: string; pruned: number }> {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new Error(`${dir} does not exist inside the webserver container - mount the share there first`);
  }
  const dest = path.join(dir, archive.filename);
  // Copied to a temporary name and renamed, so a reader of the share - or
  // the retention below on the next run - never sees a half-written
  // archive under the real name.
  const partial = `${dest}.partial`;
  await fs.promises.copyFile(archive.path, partial);
  await fs.promises.chmod(partial, 0o600);
  await fs.promises.rename(partial, dest);
  const stale = archivesToPrune(await fs.promises.readdir(dir), keep);
  for (const name of stale) await fs.promises.rm(path.join(dir, name), { force: true });
  return { location: dest, pruned: stale.length };
}

async function deliverToS3(s: BackupScheduleSettings, archive: { path: string; filename: string }): Promise<{ location: string; pruned: number }> {
  const cfg: S3Config = {
    endpoint: s.s3.endpoint!,
    region: s.s3.region,
    bucket: s.s3.bucket!,
    accessKey: s.s3.accessKey!,
    secretKey: s.s3.secretKey!,
    pathStyle: s.s3.pathStyle,
  };
  const ca = await caBundle();
  const key = `${s.s3.prefix}${archive.filename}`;
  await putObjectFromFile(cfg, key, archive.path, ca);
  const stale = archivesToPrune(await listObjects(cfg, s.s3.prefix, ca), s.keep);
  for (const k of stale) await deleteObject(cfg, k, ca);
  return { location: `s3://${cfg.bucket}/${key}`, pruned: stale.length };
}

export interface BackupRunResult {
  ok: boolean;
  location?: string;
  bytes?: number;
  pruned?: number;
  error?: string;
}

let running = false;

// One run: build the archive, deliver it, prune, record the outcome. A
// failure is recorded and alerted rather than thrown - this runs unattended,
// and a backup that fails silently is the failure that matters most.
export async function runScheduledBackup(trigger: string): Promise<BackupRunResult> {
  if (running) return { ok: false, error: "a backup is already running" };
  running = true;
  const s = await getBackupSchedule();
  const startedAt = new Date();
  let archive;
  try {
    const missing = missingBackupSettings(s);
    if (missing.length > 0) throw new Error(`not configured: ${missing.join(", ")}`);
    archive = await createBackupArchive(trigger);
    const delivered = s.target === "directory" ? await deliverToDirectory(s.directory!, archive, s.keep) : await deliverToS3(s, archive);
    await db
      .updateTable("app_settings")
      .set({
        backup_last_run_at: startedAt,
        backup_last_status: "succeeded",
        backup_last_error: null,
        backup_last_location: delivered.location,
        backup_last_bytes: archive.bytes,
        backup_last_success_at: new Date(),
      })
      .where("id", "=", 1)
      .execute();
    logger.info({ event: "backup.scheduled_succeeded", trigger, location: delivered.location, bytes: archive.bytes, pruned: delivered.pruned });
    await recordAudit("backup.scheduled_succeeded", trigger, undefined, { location: delivered.location, bytes: archive.bytes, pruned: delivered.pruned });
    return { ok: true, location: delivered.location, bytes: archive.bytes, pruned: delivered.pruned };
  } catch (err) {
    const message = err instanceof BackupSpaceError || err instanceof Error ? err.message : String(err);
    await db
      .updateTable("app_settings")
      .set({ backup_last_run_at: startedAt, backup_last_status: "failed", backup_last_error: message.slice(0, 1000) })
      .where("id", "=", 1)
      .execute();
    logger.error({ event: "backup.scheduled_failed", trigger, target: s.target, err: message });
    await recordAudit("backup.scheduled_failed", trigger, undefined, { target: s.target, error: message });
    await dispatchWebhook("backup.failed", `Scheduled backup to ${s.target === "s3" ? "S3" : s.directory ?? "a directory"} failed: ${message}`, {
      target: s.target,
      error: message,
      last_success_at: s.last.successAt,
    });
    return { ok: false, error: message };
  } finally {
    archive?.cleanup();
    running = false;
  }
}

// Fires once per UTC day, in the configured hour - persisted, so a restart
// inside that hour does not run it twice. The date is claimed before the
// run rather than after, so a run that takes longer than the ticker's
// interval is not started a second time.
export async function backupTick(now: Date = new Date()): Promise<boolean> {
  const row = await db
    .selectFrom("app_settings")
    .select(["backup_schedule_enabled", "backup_hour_utc", "backup_last_date"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  if (!row.backup_schedule_enabled || now.getUTCHours() !== row.backup_hour_utc) return false;
  const today = now.toISOString().slice(0, 10);
  if (toDateOnlyString(row.backup_last_date) === today) return false;
  const claimed = await db
    .updateTable("app_settings")
    .set({ backup_last_date: today })
    .where("id", "=", 1)
    .where((eb) => eb.or([eb("backup_last_date", "is", null), eb("backup_last_date", "<>", today)]))
    .executeTakeFirst();
  if (claimed.numUpdatedRows === 0n) return false;
  await runScheduledBackup("schedule");
  return true;
}

export function startScheduledBackups(): void {
  setInterval(() => {
    backupTick().catch((err) =>
      logger.error({ event: "backup.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}
