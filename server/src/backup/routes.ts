import { Router } from "express";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { z } from "zod";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import {
  BackupSpaceError,
  createBackupArchive,
  estimateBackup,
  requiredFreeBytes,
} from "./archive";
import { RestoreError, RestoreSchemaError, restoreFromArchive } from "./restore";
import { getBackupSchedule, missingBackupSettings, runScheduledBackup, setBackupSchedule } from "./schedule";

// Mounted under the settings router, so requireAuth + requireAdmin
// already apply. Both actions warrant that tier on their own: the archive
// contains every password hash and the TLS private key, and the restore
// replaces the entire database.
export const backupRouter = Router();

backupRouter.get(
  "/estimate",
  asyncHandler(async (_req, res) => {
    const estimate = await estimateBackup();
    res.json({ ...estimate, requiredBytes: requiredFreeBytes(estimate.totalBytes) });
  })
);

// A plain GET so the browser streams it straight to disk. Buffering a
// backup through fetch() into a Blob first would put the whole thing in
// browser memory, which is fine at 12 MB and not at all fine once a fleet
// has a few GB of screenshots. The whole archive is built before a single
// byte is sent, so a failure still lands as a normal error response
// rather than a truncated file.
backupRouter.get(
  "/download",
  asyncHandler(async (req, res) => {
    const actor = req.session.username;
    let archive;
    try {
      archive = await createBackupArchive(actor ?? "unknown");
    } catch (err) {
      if (err instanceof BackupSpaceError) {
        res.status(507).json({ error: err.message });
        return;
      }
      throw err;
    }

    logger.info({
      event: "backup.created",
      actor,
      filename: archive.filename,
      bytes: archive.bytes,
      schema_migration: archive.manifest.schema_migration,
    });
    await recordAudit("backup.created", actor, req.ip, {
      filename: archive.filename,
      bytes: archive.bytes,
      schema_migration: archive.manifest.schema_migration,
    });

    res.download(archive.path, archive.filename, (err) => {
      if (err) {
        logger.warn({
          event: "backup.download_failed",
          err: err instanceof Error ? err.message : String(err),
        });
      }
      archive.cleanup();
    });
  })
);

// Disk-backed rather than multer's in-memory storage (what the TLS
// certificate upload beside it uses): a PEM file is kilobytes, a backup
// archive is however large the fleet's screenshots are.
const uploadDir = path.join(os.tmpdir(), "porttorch-uploads");
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({ destination: uploadDir }),
  limits: { fileSize: 16 * 1024 * 1024 * 1024 },
});

backupRouter.post(
  "/restore",
  // Checked before multer starts writing: an upload that cannot fit is
  // better refused outright than after filling the remaining disk with a
  // file that then has to be unpacked on top of itself.
  asyncHandler(async (req, res, next) => {
    const declared = Number(req.headers["content-length"] ?? 0);
    if (declared > 0) {
      try {
        const stat = fs.statfsSync(uploadDir);
        const free = Number(stat.bavail) * Number(stat.bsize);
        if (free < declared * 2 + 128 * 1024 * 1024) {
          res.status(507).json({
            error:
              `Not enough free disk space to accept this upload: ${Math.round(free / 1048576)} MB free, ` +
              `the archive alone is ${Math.round(declared / 1048576)} MB and has to be unpacked on top of that.`,
          });
          return;
        }
      } catch {
        // Can't measure - let it proceed rather than blocking a restore
        // on a failed statfs.
      }
    }
    next();
  }),
  upload.single("archive"),
  asyncHandler(async (req, res) => {
    const actor = req.session.username;
    const file = req.file;
    if (!file) {
      res.status(400).json({ error: "No archive was uploaded." });
      return;
    }

    logger.warn({ event: "backup.restore_started", actor, bytes: file.size });

    try {
      const result = await restoreFromArchive(file.path);

      // Written before the process exits, and deliberately into the
      // just-restored database: this row is the only in-app record that
      // the restore happened at all, since everything else in the audit
      // log is now the backup's own history.
      await recordAudit("backup.restored", actor, req.ip, {
        backup_created_at: result.manifest.created_at,
        backup_source: result.manifest.source,
        schema_migration: result.manifest.schema_migration,
        screenshots_restored: result.screenshotsRestored,
        warning: result.warning,
      });
      logger.warn({
        event: "backup.restored",
        actor,
        backup_created_at: result.manifest.created_at,
        schema_migration: result.manifest.schema_migration,
        screenshots_restored: result.screenshotsRestored,
      });

      res.json({
        ok: true,
        manifest: result.manifest,
        screenshotsRestored: result.screenshotsRestored,
        warning: result.warning,
        restarting: true,
      });

      // The process has to go: its connection pool holds cached query
      // plans for tables that were just dropped and recreated, and its
      // in-memory caches (app settings, CA bundle, SMTP transporter) now
      // describe a database that no longer exists. Exiting is also what
      // gets migrations run against a restored older schema, since the
      // entrypoint runs them on every boot. Compose restarts the
      // container (restart: unless-stopped).
      setTimeout(() => {
        logger.warn({ event: "backup.restart_after_restore" });
        process.exit(0);
      }, 500);
    } catch (err) {
      if (err instanceof RestoreSchemaError) {
        res.status(409).json({ error: err.message });
        return;
      }
      if (err instanceof RestoreError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    } finally {
      try {
        fs.rmSync(file.path, { force: true });
      } catch {
        // Best effort.
      }
    }
  })
);

// --- Scheduled backups -------------------------------------------------------
//
// The same archive as the download above, made on a schedule and delivered
// off this host - see schedule.ts.
function clientSchedule(s: Awaited<ReturnType<typeof getBackupSchedule>>) {
  const { secretKey, ...s3 } = s.s3;
  return { ...s, s3: { ...s3, secretKeySet: Boolean(secretKey) }, missing: missingBackupSettings(s) };
}

backupRouter.get(
  "/schedule",
  asyncHandler(async (_req, res) => {
    res.json(clientSchedule(await getBackupSchedule()));
  })
);

const scheduleSchema = z.object({
  enabled: z.boolean(),
  hourUtc: z.number().int().min(0).max(23),
  keep: z.number().int().min(1).max(365),
  target: z.enum(["directory", "s3"]),
  // An absolute path inside the container: a relative one would land
  // wherever the process happens to run from.
  directory: z.string().trim().max(500).refine((v) => v.startsWith("/"), { message: "must be an absolute path" }).nullable(),
  s3: z.object({
    endpoint: z.string().trim().url().max(500).nullable(),
    region: z.string().trim().min(1).max(50),
    bucket: z.string().trim().min(3).max(63).regex(/^[a-z0-9.-]+$/, "bucket names are lower-case letters, digits, dots and hyphens").nullable(),
    // Empty, or ending in "/" so the archives sit under it as a folder.
    prefix: z.string().trim().max(200).refine((v) => v === "" || v.endsWith("/"), { message: "must be empty or end with /" }),
    accessKey: z.string().trim().min(1).max(200).nullable(),
    secretKey: z.string().min(1).max(500).nullable().optional(),
    pathStyle: z.boolean(),
  }),
});

backupRouter.put(
  "/schedule",
  asyncHandler(async (req, res) => {
    const parsed = scheduleSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const current = await getBackupSchedule();
    const merged = { ...parsed.data, s3: { ...parsed.data.s3, secretKey: parsed.data.s3.secretKey === undefined ? current.s3.secretKey : parsed.data.s3.secretKey } };
    const missing = missingBackupSettings(merged);
    // Switching on a schedule that can only fail would just produce a
    // failure alert every night.
    if (parsed.data.enabled && missing.length > 0) {
      res.status(400).json({ error: `cannot enable scheduled backups without: ${missing.join(", ")}` });
      return;
    }
    await setBackupSchedule(parsed.data);
    logger.info({
      event: "settings.backup_schedule_updated",
      enabled: parsed.data.enabled,
      target: parsed.data.target,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    await recordAudit("settings.backup_schedule_updated", req.session.username, req.ip, {
      enabled: parsed.data.enabled,
      target: parsed.data.target,
      hour_utc: parsed.data.hourUtc,
      keep: parsed.data.keep,
      secret_changed: parsed.data.s3.secretKey !== undefined,
    });
    res.json(clientSchedule(await getBackupSchedule()));
  })
);

// Runs the scheduled backup now, with the saved settings - the way to
// test a destination before relying on it at 2 a.m. The response is the
// outcome; a delivery failure is a 200 with ok:false, like the SMTP test.
backupRouter.post(
  "/schedule/run-now",
  asyncHandler(async (req, res) => {
    const result = await runScheduledBackup(req.session.username ?? "unknown");
    res.json({ ...result, schedule: clientSchedule(await getBackupSchedule()) });
  })
);
