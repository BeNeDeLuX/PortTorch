import { Router } from "express";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
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
