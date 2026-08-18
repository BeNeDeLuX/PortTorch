import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { config } from "../config";
import { getCurrentCertInfo, saveCertKeyPair, validateCertKeyPair } from "../tls/certUpload";
import { getActiveHttpsServer } from "../tls/activeServer";
import {
  getAppSettings,
  setHostRetentionDays,
  setRequireAdminTotp,
  setScanQueueWarningThreshold,
  setStaleScanThresholdMinutes,
} from "./appSettings";
import { runRetentionSweep } from "../retention";

// Everything here is admin-only, like scanner agents/schedules/webhooks/
// excludes/user management (see CLAUDE.md's "Roles and permissions") -
// replacing the webserver's own TLS listener certificate is at least as
// sensitive as any of those.
export const settingsRouter = Router();
settingsRouter.use(requireAuth, requireAdmin);

settingsRouter.get("/tls-certificate", asyncHandler(async (req, res) => {
  res.json(getCurrentCertInfo(config.certDir));
}));

// PEM text is small - 256KB is generous even for a full chain with
// several intermediates, matching the spirit of the ingest routes'
// image-upload size limit (a defensive cap, not a tight budget).
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 256 * 1024 } });

settingsRouter.post(
  "/tls-certificate",
  upload.fields([
    { name: "certificate", maxCount: 1 },
    { name: "privateKey", maxCount: 1 },
  ]),
  asyncHandler(async (req, res) => {
    const files = req.files as { certificate?: Express.Multer.File[]; privateKey?: Express.Multer.File[] } | undefined;
    const certFile = files?.certificate?.[0];
    const keyFile = files?.privateKey?.[0];
    if (!certFile || !keyFile) {
      res.status(400).json({ error: "both a certificate file and a private key file are required" });
      return;
    }
    const certPem = certFile.buffer.toString("utf8");
    const keyPem = keyFile.buffer.toString("utf8");

    let info;
    try {
      info = validateCertKeyPair(certPem, keyPem);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : "invalid certificate or private key" });
      return;
    }

    saveCertKeyPair(config.certDir, certPem, keyPem);

    // Applies immediately to the live listener - Node's setSecureContext
    // affects only new connections from this point on, existing
    // connections keep whatever context they negotiated with, so this
    // never drops anyone mid-request. Falls back to a log-only warning
    // if somehow called before index.ts registered the server (e.g. a
    // future test harness) - the file on disk is still correctly
    // updated either way, so a restart would pick it up regardless.
    const server = getActiveHttpsServer();
    if (server) {
      server.setSecureContext({ cert: certPem, key: keyPem });
    } else {
      logger.warn({ event: "settings.tls_certificate_no_active_server" });
    }

    logger.info({
      event: "settings.tls_certificate_updated",
      updated_by: req.session.username,
      source_ip: req.ip,
      subject_cn: info.subjectCN,
      issuer_cn: info.issuerCN,
      valid_to: info.validTo,
    });
    recordAudit("settings.tls_certificate_updated", req.session.username, req.ip, {
      subject_cn: info.subjectCN,
      issuer_cn: info.issuerCN,
      valid_to: info.validTo,
    });

    res.json(info);
  })
);

settingsRouter.get("/app", asyncHandler(async (_req, res) => {
  res.json(await getAppSettings());
}));

// Both fields optional - a genuine partial update, same "distinguish
// omitted from explicit" convention as PATCH /auth/preferences, since the
// Settings page saves the 2FA-enforcement toggle and the retention-days
// field independently rather than as one combined form.
const appSettingsSchema = z.object({
  requireAdminTotp: z.boolean().optional(),
  hostRetentionDays: z.number().int().min(0).optional(),
  staleScanThresholdMinutes: z.number().int().min(1).optional(),
  scanQueueWarningThreshold: z.number().int().min(1).optional(),
});

// The first admin to flip this on effectively binds every admin account
// (including their own, if 2FA isn't already enabled on it) - see
// auth/routes.ts's totpSetupRequired for the actual enforcement point.
// Any admin can flip it back off, same as any other admin-only setting -
// there's no separate "super admin" tier in this app that could lock a
// regular admin out of changing it.
settingsRouter.patch("/app", asyncHandler(async (req, res) => {
  const parsed = appSettingsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  if ("requireAdminTotp" in req.body && parsed.data.requireAdminTotp !== undefined) {
    await setRequireAdminTotp(parsed.data.requireAdminTotp);
    logger.info({
      event: "settings.require_admin_totp_updated",
      require_admin_totp: parsed.data.requireAdminTotp,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.require_admin_totp_updated", req.session.username, req.ip, {
      require_admin_totp: parsed.data.requireAdminTotp,
    });
  }

  if ("hostRetentionDays" in req.body && parsed.data.hostRetentionDays !== undefined) {
    await setHostRetentionDays(parsed.data.hostRetentionDays);
    logger.info({
      event: "settings.host_retention_days_updated",
      host_retention_days: parsed.data.hostRetentionDays,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.host_retention_days_updated", req.session.username, req.ip, {
      host_retention_days: parsed.data.hostRetentionDays,
    });
  }

  if ("staleScanThresholdMinutes" in req.body && parsed.data.staleScanThresholdMinutes !== undefined) {
    await setStaleScanThresholdMinutes(parsed.data.staleScanThresholdMinutes);
    logger.info({
      event: "settings.stale_scan_threshold_minutes_updated",
      stale_scan_threshold_minutes: parsed.data.staleScanThresholdMinutes,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.stale_scan_threshold_minutes_updated", req.session.username, req.ip, {
      stale_scan_threshold_minutes: parsed.data.staleScanThresholdMinutes,
    });
  }

  if ("scanQueueWarningThreshold" in req.body && parsed.data.scanQueueWarningThreshold !== undefined) {
    await setScanQueueWarningThreshold(parsed.data.scanQueueWarningThreshold);
    logger.info({
      event: "settings.scan_queue_warning_threshold_updated",
      scan_queue_warning_threshold: parsed.data.scanQueueWarningThreshold,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.scan_queue_warning_threshold_updated", req.session.username, req.ip, {
      scan_queue_warning_threshold: parsed.data.scanQueueWarningThreshold,
    });
  }

  res.json(await getAppSettings());
}));

// Runs the exact same sweep the hourly ticker does (see retention.ts's
// runRetentionSweep) - lets an admin apply a just-changed retention
// window immediately, or clear out a known-stale backlog, without
// waiting up to an hour for the next scheduled tick.
settingsRouter.post("/retention/run-now", asyncHandler(async (req, res) => {
  const result = await runRetentionSweep();

  logger.info({
    event: "settings.retention_run_now",
    purged_count: result.purged,
    triggered_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("settings.retention_run_now", req.session.username, req.ip, { purged_count: result.purged });

  res.json(result);
}));
