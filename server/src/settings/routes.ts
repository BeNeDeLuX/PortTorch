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
  setDigestEmailHourUtc,
  setEpssAlertThreshold,
  setQueueBacklogThresholdMinutes,
  setScanLogRetentionDays,
  setScanQueueWarningThreshold,
  setSmtpSettings,
  setStaleScanThresholdMinutes,
} from "./appSettings";
import { buildTransporter, resetSmtpTransporter, senderAddress } from "../webhooks/email";
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

// The stored SMTP password must never leave the server - it's the one
// app_settings value that's a live credential rather than a preference.
// Replaced with a boolean so the Settings form can still show whether one
// is set (and therefore whether leaving its field blank means "keep" or
// "none") without ever transmitting it.
async function clientAppSettings() {
  const settings = await getAppSettings();
  const { password, ...smtp } = settings.smtp;
  return { ...settings, smtp: { ...smtp, passwordSet: Boolean(password) } };
}

settingsRouter.get("/app", asyncHandler(async (_req, res) => {
  res.json(await clientAppSettings());
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
  scanLogRetentionDays: z.number().int().min(0).optional(),
  digestEmailHourUtc: z.number().int().min(0).max(23).optional(),
  epssAlertThreshold: z.number().min(0).max(1).optional(),
  queueBacklogThresholdMinutes: z.number().int().min(1).optional(),
  // Saved as one object rather than field-by-field: these only make sense
  // together (a host without its port/auth is not a usable half-state),
  // and the form submits them as one section. password is the exception -
  // optional even within the object, since the form can't prefill what
  // the API never returns, so omitting it means "keep the stored one".
  smtp: z
    .object({
      host: z.string().trim().min(1).nullable(),
      port: z.number().int().min(1).max(65535),
      secure: z.boolean(),
      user: z.string().trim().min(1).nullable(),
      password: z.string().min(1).nullable().optional(),
      from: z.string().trim().min(1).nullable(),
    })
    .optional(),
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

  if ("scanLogRetentionDays" in req.body && parsed.data.scanLogRetentionDays !== undefined) {
    await setScanLogRetentionDays(parsed.data.scanLogRetentionDays);
    logger.info({
      event: "settings.scan_log_retention_updated",
      scan_log_retention_days: parsed.data.scanLogRetentionDays,
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.scan_log_retention_updated", req.session.username, req.ip, {
      scan_log_retention_days: parsed.data.scanLogRetentionDays,
    });
  }

  // These three share one shape, so they share one loop rather than three
  // near-identical blocks - each still gets its own log line and audit
  // entry, which is what actually matters for traceability.
  const simpleSettings: Array<[keyof typeof parsed.data, string, (v: never) => Promise<void>]> = [
    ["digestEmailHourUtc", "settings.digest_hour_updated", setDigestEmailHourUtc as (v: never) => Promise<void>],
    ["epssAlertThreshold", "settings.epss_threshold_updated", setEpssAlertThreshold as (v: never) => Promise<void>],
    [
      "queueBacklogThresholdMinutes",
      "settings.queue_backlog_threshold_updated",
      setQueueBacklogThresholdMinutes as (v: never) => Promise<void>,
    ],
  ];
  for (const [key, event, setter] of simpleSettings) {
    const value = parsed.data[key];
    if (key in req.body && value !== undefined) {
      await setter(value as never);
      logger.info({ event, value, updated_by: req.session.username, source_ip: req.ip });
      recordAudit(event, req.session.username, req.ip, { [key]: value });
    }
  }

  if ("smtp" in req.body && parsed.data.smtp !== undefined) {
    await setSmtpSettings(parsed.data.smtp);
    // The transporter is cached for the process lifetime, so without this
    // an admin fixing a mail server here would keep hitting the old one
    // until the next restart - precisely the loop moving these settings
    // into the database was meant to end.
    resetSmtpTransporter();
    logger.info({
      event: "settings.smtp_updated",
      smtp_host: parsed.data.smtp.host,
      smtp_port: parsed.data.smtp.port,
      smtp_secure: parsed.data.smtp.secure,
      // Never the password, and never even whether it changed - only that
      // the settings were saved, same discipline as every other log line
      // in this codebase (see CLAUDE.md's logging section).
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.smtp_updated", req.session.username, req.ip, {
      smtp_host: parsed.data.smtp.host,
      smtp_port: parsed.data.smtp.port,
    });
  }

  res.json(await clientAppSettings());
}));

// Runs the exact same sweep the hourly ticker does (see retention.ts's
// runRetentionSweep) - lets an admin apply a just-changed retention
// window immediately, or clear out a known-stale backlog, without
// waiting up to an hour for the next scheduled tick.
settingsRouter.post("/retention/run-now", asyncHandler(async (req, res) => {
  const result = await runRetentionSweep();

  logger.info({
    event: "settings.retention_run_now",
    purged_hosts: result.purgedHosts,
    purged_audit_log_entries: result.purgedAuditLogEntries,
    triggered_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("settings.retention_run_now", req.session.username, req.ip, {
    purged_hosts: result.purgedHosts,
    purged_audit_log_entries: result.purgedAuditLogEntries,
  });

  res.json(result);
}));

const smtpTestSchema = z.object({ to: z.string().trim().email() });

// Sends a real message through the *saved* settings, rather than
// nodemailer's verify() - verify only proves the connection and auth
// work, and the failures people actually hit when configuring mail are
// further along than that: a sender address the server refuses to relay
// for, a recipient domain it won't accept, a silently-dropped message.
// Only a delivered test email answers "is this actually working".
//
// Deliberately tests what's stored, not what's in the form: an admin
// saves, then tests, and the result describes the configuration that
// alerts will really use. Same shape as the Webhooks page's own per-
// channel Test button.
settingsRouter.post("/smtp/test", asyncHandler(async (req, res) => {
  const parsed = smtpTestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "a valid recipient email address is required" });
    return;
  }

  const { smtp } = await getAppSettings();
  const transport = buildTransporter(smtp);
  if (!transport) {
    res.status(400).json({ error: "no mail server is configured - set a host first" });
    return;
  }

  try {
    await transport.sendMail({
      from: senderAddress(smtp),
      to: parsed.data.to,
      subject: "PortTorch: SMTP test",
      text: "This is a test message from PortTorch. If you received it, alert emails will work.",
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn({ event: "settings.smtp_test_failed", error: message, triggered_by: req.session.username });
    // 200 with ok:false, not a 5xx: the request itself succeeded, and the
    // delivery failure is the answer the admin asked for - same
    // convention as the webhook /test endpoint.
    res.json({ ok: false, error: message });
    return;
  }

  logger.info({ event: "settings.smtp_test_sent", triggered_by: req.session.username, source_ip: req.ip });
  recordAudit("settings.smtp_test_sent", req.session.username, req.ip, { to: parsed.data.to });
  res.json({ ok: true });
}));
