import { Router } from "express";
import fs from "fs";
import path from "path";
import multer from "multer";
import { z } from "zod";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { getWebserverReleaseStatus, syncWebserverRelease } from "../webserverUpdate/dockerHubSync";
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
  setScannerOfflineThresholdMinutes,
  setHostDisappearedThresholdDays,
  setNetworkCoverageStaleDays,
  setScanLogRetentionDays,
  setScanQueueWarningThreshold,
  setHecSettings,
  setSmtpSettings,
  setStaleScanThresholdMinutes,
} from "./appSettings";
import { buildTransporter, resetSmtpTransporter, senderAddress } from "../webhooks/email";
import { postToHec } from "../hec/client";
import { CaCertificateError, caBundle, parseCaCertificate, resetCaBundle } from "../settings/caCertificates";
import { runHecForward } from "../hec/forwarder";
import { runRetentionSweep } from "../retention";
import { backupRouter } from "../backup/routes";

// Everything here is admin-only, like scanner agents/schedules/webhooks/
// excludes/user management (see CLAUDE.md's "Roles and permissions") -
// replacing the webserver's own TLS listener certificate is at least as
// sensitive as any of those.
export const settingsRouter = Router();
settingsRouter.use(requireAuth, requireAdmin);

// Creating and restoring a full backup - its own module, since the
// archive format is shared with scripts/backup.sh and has nothing to do
// with the individual settings around it.
settingsRouter.use("/backup", backupRouter);

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
  // Same treatment for the HEC token as for the SMTP password: an admin
  // who can set it must not be able to read back one someone else set.
  const { token, ...hec } = settings.hec;
  return {
    ...settings,
    smtp: { ...smtp, passwordSet: Boolean(password) },
    hec: { ...hec, tokenSet: Boolean(token) },
  };
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
  scannerOfflineThresholdMinutes: z.number().int().min(1).optional(),
  // Days, not minutes - the signal is only as fast as whatever schedule
  // covers that host, so anything under a day would alert on every host
  // between scans. See the presence_alerts migration.
  hostDisappearedThresholdDays: z.number().int().min(1).optional(),
  // Days as well, and for the same reason: coverage is measured against
  // how often a range is actually swept, which is a schedule-scale
  // interval, not a minutes-scale one.
  networkCoverageStaleDays: z.number().int().min(1).optional(),
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
      // Optional, and omitted means "keep the stored value" - same
      // treatment as password above, and for the same reason: making it
      // required would 400 every caller written before it existed, and
      // defaulting it to true would silently re-enable verification for
      // someone who had turned it off and then saved an unrelated field.
      verifyTls: z.boolean().optional(),
    })
    .optional(),
  // One object for the same reason as smtp: a collector URL without its
  // token is not a usable half-state, and the form saves them together.
  hec: z
    .object({
      url: z.string().trim().min(1).nullable(),
      token: z.string().min(1).nullable().optional(),
      auditEnabled: z.boolean(),
      scanLogEnabled: z.boolean(),
      index: z.string().trim().min(1).nullable(),
      sourcetype: z.string().trim().min(1).nullable(),
      verifyTls: z.boolean(),
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

  // These share one shape, so they share one loop rather than five
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
    [
      "scannerOfflineThresholdMinutes",
      "settings.scanner_offline_threshold_updated",
      setScannerOfflineThresholdMinutes as (v: never) => Promise<void>,
    ],
    [
      "hostDisappearedThresholdDays",
      "settings.host_disappeared_threshold_updated",
      setHostDisappearedThresholdDays as (v: never) => Promise<void>,
    ],
    [
      "networkCoverageStaleDays",
      "settings.network_coverage_stale_days_updated",
      setNetworkCoverageStaleDays as (v: never) => Promise<void>,
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

  if ("hec" in req.body && parsed.data.hec !== undefined) {
    await setHecSettings(parsed.data.hec);
    logger.info({
      event: "settings.hec_updated",
      hec_url: parsed.data.hec.url,
      hec_audit_enabled: parsed.data.hec.auditEnabled,
      hec_scan_log_enabled: parsed.data.hec.scanLogEnabled,
      hec_verify_tls: parsed.data.hec.verifyTls,
      // Never the token, and never even whether it changed - same
      // discipline as the SMTP password above.
      updated_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("settings.hec_updated", req.session.username, req.ip, {
      hec_url: parsed.data.hec.url,
      hec_audit_enabled: parsed.data.hec.auditEnabled,
      hec_scan_log_enabled: parsed.data.hec.scanLogEnabled,
    });
  }

  res.json(await clientAppSettings());
}));

// What the forwarder has actually managed to do - the answer to "is this
// working?", which a saved configuration on its own doesn't give. Read
// straight from hec_state rather than recomputed, so it reflects the real
// cursor rather than an estimate.
settingsRouter.get("/hec/status", asyncHandler(async (_req, res) => {
  const row = await db
    .selectFrom("hec_state")
    .select(["audit_cursor", "scan_log_cursor_at", "last_success_at", "last_attempt_at", "last_error", "events_forwarded"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  res.json({
    auditCursor: row.audit_cursor,
    scanLogCursorAt: row.scan_log_cursor_at,
    lastSuccessAt: row.last_success_at,
    lastAttemptAt: row.last_attempt_at,
    lastError: row.last_error,
    eventsForwarded: Number(row.events_forwarded),
  });
}));

// Sends one real event to the collector, so an admin finds out here
// whether the URL, token and TLS setting are right rather than by
// noticing nothing ever arrives in the SIEM.
settingsRouter.post("/hec/test", asyncHandler(async (req, res) => {
  const { hec } = await getAppSettings();
  if (!hec.url || !hec.token) {
    res.status(400).json({ error: "set a collector URL and token first" });
    return;
  }

  const result = await postToHec(
    hec,
    [
      {
        time: Date.now() / 1000,
        source: "porttorch:test",
        sourcetype: hec.sourcetype || "porttorch:test",
        ...(hec.index ? { index: hec.index } : {}),
        event: {
          event: "hec.test",
          message: "PortTorch HEC test event. If you can search for this, log forwarding works.",
          triggered_by: req.session.username ?? null,
        },
      },
    ],
    await caBundle()
  );

  if (!result.ok) {
    logger.warn({ event: "settings.hec_test_failed", error: result.error, triggered_by: req.session.username });
    // 200 with ok:false, like the SMTP and webhook tests: the request
    // itself succeeded, and the delivery failure is the answer.
    res.json({ ok: false, error: result.error });
    return;
  }

  logger.info({ event: "settings.hec_test_sent", triggered_by: req.session.username, source_ip: req.ip });
  recordAudit("settings.hec_test_sent", req.session.username, req.ip, { hec_url: hec.url });
  res.json({ ok: true });
}));

// The scheduled forwarder's own logic, exposed as a manual trigger - same
// pattern as POST /retention/run-now, and the thing an admin wants right
// after switching this on rather than waiting out the interval.
settingsRouter.post("/hec/forward-now", asyncHandler(async (req, res) => {
  const counts = await runHecForward();
  logger.info({
    event: "settings.hec_forward_triggered",
    audit_events: counts.audit,
    scan_log_events: counts.scanLog,
    triggered_by: req.session.username,
  });
  res.json(counts);
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
  const transport = buildTransporter(smtp, await caBundle());
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

// Trust anchors for this webserver's *outbound* TLS - the mail relay and
// the HEC collector. Deliberately not related to the webserver's own
// listener certificate above, which is what clients verify when they
// connect *to* PortTorch; these are the opposite direction and share
// nothing but the word "certificate".
settingsRouter.get("/ca-certificates", asyncHandler(async (_req, res) => {
  const rows = await db
    .selectFrom("trusted_ca_certificates")
    // Never the PEM itself: it is not a secret, but the list is a summary
    // and a page that dumps several certificates of base64 is unreadable.
    .select(["id", "name", "subject", "issuer", "not_before", "not_after", "fingerprint_sha256", "uploaded_by", "created_at"])
    .orderBy("created_at", "desc")
    .execute();
  res.json(rows);
}));

const caUploadSchema = z.object({
  name: z.string().trim().min(1).max(100),
  pem: z.string().min(1).max(64 * 1024),
});

settingsRouter.post("/ca-certificates", asyncHandler(async (req, res) => {
  const parsed = caUploadSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  let cert;
  try {
    cert = parseCaCertificate(parsed.data.pem);
  } catch (err) {
    if (err instanceof CaCertificateError) {
      res.status(400).json({ error: err.message });
      return;
    }
    throw err;
  }

  const existing = await db
    .selectFrom("trusted_ca_certificates")
    .select(["id", "name"])
    .where("fingerprint_sha256", "=", cert.fingerprintSha256)
    .executeTakeFirst();
  if (existing) {
    res.status(409).json({ error: `this certificate is already trusted, as "${existing.name}"` });
    return;
  }

  const row = await db
    .insertInto("trusted_ca_certificates")
    .values({
      name: parsed.data.name,
      pem: cert.pem,
      subject: cert.subject,
      issuer: cert.issuer,
      not_before: cert.notBefore,
      not_after: cert.notAfter,
      fingerprint_sha256: cert.fingerprintSha256,
      uploaded_by: req.session.username ?? null,
    })
    .returning(["id", "name", "subject", "issuer", "not_before", "not_after", "fingerprint_sha256", "created_at"])
    .executeTakeFirstOrThrow();

  // Both caches have to go: the bundle itself, and the SMTP transporter,
  // which captured the old bundle when it was built. Without the second
  // one an admin would upload their CA and keep hitting the same
  // verification error until the process restarted - the exact loop that
  // moving these settings into the database was meant to end.
  resetCaBundle();
  resetSmtpTransporter();

  logger.info({
    event: "ca_certificate.uploaded",
    ca_certificate_id: row.id,
    name: row.name,
    subject: row.subject,
    not_after: row.not_after,
    uploaded_by: req.session.username,
  });
  recordAudit("ca_certificate.uploaded", req.session.username, req.ip, {
    ca_certificate_id: row.id,
    name: row.name,
    subject: row.subject,
    fingerprint_sha256: row.fingerprint_sha256,
  });

  res.status(201).json(row);
}));

settingsRouter.delete("/ca-certificates/:id", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid certificate id" });
    return;
  }
  const result = await db.deleteFrom("trusted_ca_certificates").where("id", "=", req.params.id).executeTakeFirst();
  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "certificate not found" });
    return;
  }

  resetCaBundle();
  resetSmtpTransporter();
  logger.info({ event: "ca_certificate.deleted", ca_certificate_id: req.params.id, deleted_by: req.session.username });
  recordAudit("ca_certificate.deleted", req.session.username, req.ip, { ca_certificate_id: req.params.id });
  res.status(204).end();
}));

// Where the database and the screenshot directory are actually going.
// Deliberately on Settings and loaded on demand rather than a Fleet
// Health card: the screenshot figure needs a real directory scan, which
// must not ride on a page that polls every few seconds. The tables listed
// are the append-only ones that grow with every scan (see CLAUDE.md's
// Database shape notes) - the point is to make growth visible before it
// becomes a problem, since deciding what to cap without knowing the
// numbers would just be guessing.
// Whether a newer webserver image than the running one is published.
// Mirrors GET /api/agents/latest-release for the scanner, including its
// access level: read-only fleet information every viewer of Fleet Health
// needs, even though acting on it is an operator's job on the host, not a
// dashboard action. Unlike the scanner, the webserver cannot update
// itself - it runs in the container it would have to replace - so this
// reports and links, it never offers a button.
settingsRouter.get("/webserver-release", asyncHandler(async (_req, res) => {
  res.json(await getWebserverReleaseStatus());
}));

// The manual counterpart to the hourly sync, so a just-published image
// doesn't sit invisible for up to an hour. Admin-only, unlike the GET
// above: a real outbound request plus a DB write, same split as the
// scanner's own latest-release/refresh.
settingsRouter.post("/webserver-release/refresh", asyncHandler(async (req, res) => {
  try {
    await syncWebserverRelease();
  } catch (err) {
    logger.warn({
      event: "webserver_release_sync.manual_refresh_failed",
      err: err instanceof Error ? err.message : String(err),
    });
    res.status(502).json({ error: err instanceof Error ? err.message : "failed to reach Docker Hub" });
    return;
  }
  logger.info({ event: "webserver_release_sync.manual_refresh", triggered_by: req.session.username, source_ip: req.ip });
  res.json(await getWebserverReleaseStatus());
}));

settingsRouter.get("/storage", asyncHandler(async (_req, res) => {
  const sizes = await sql<{ table_name: string; bytes: string; rows: string }>`
    SELECT t.table_name, pg_total_relation_size(t.table_name)::text AS bytes, t.rows::text AS rows
    FROM (
      VALUES
        ('host_port_observations', (SELECT count(*) FROM host_port_observations)),
        ('nuclei_findings', (SELECT count(*) FROM nuclei_findings)),
        ('screenshots', (SELECT count(*) FROM screenshots)),
        ('rdp_screenshots', (SELECT count(*) FROM rdp_screenshots)),
        ('scan_job_full_log', (SELECT count(*) FROM scan_job_full_log)),
        ('audit_log', (SELECT count(*) FROM audit_log))
    ) AS t(table_name, rows)
  `.execute(db);

  const databaseBytes = await sql<{ bytes: string }>`SELECT pg_database_size(current_database())::text AS bytes`.execute(db);

  // Counted here rather than inferred from the screenshots tables,
  // precisely so a mismatch between the two is visible: a directory
  // holding far more files than there are rows is the orphan leak the
  // retention sweep now cleans up.
  let screenshotFiles = 0;
  let screenshotBytes = 0;
  try {
    for (const entry of fs.readdirSync(path.resolve(config.screenshotDir))) {
      try {
        const stat = fs.statSync(path.join(path.resolve(config.screenshotDir), entry));
        if (!stat.isFile()) continue;
        screenshotFiles++;
        screenshotBytes += stat.size;
      } catch {
        // Raced with a delete - skip it.
      }
    }
  } catch {
    // Directory doesn't exist yet (nothing has ever been captured).
  }

  res.json({
    databaseBytes: Number(databaseBytes.rows[0].bytes),
    tables: sizes.rows.map((r) => ({ table: r.table_name, bytes: Number(r.bytes), rows: Number(r.rows) })),
    screenshots: { files: screenshotFiles, bytes: screenshotBytes },
  });
}));
