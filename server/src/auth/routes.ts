import { Router } from "express";
import type { Request, Response } from "express";
import { z } from "zod";
import qrcode from "qrcode";
import { db } from "../db";
import { hashPassword, verifyPassword } from "./password";
import { revokeUserSessions } from "./sessions";
import { requireAuth } from "./middleware";
import { isLockedOut, recordFailure, recordSuccess } from "./rateLimiter";
import { hashApiKey } from "../ingest/apiKeyAuth";
import { buildOtpauthUrl, generateRecoveryCodes, generateSecret, verifyToken } from "./totp";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { VERSION } from "../version";
import { getAppSettings } from "../settings/appSettings";

export const authRouter = Router();

interface PreferenceColumns {
  pref_theme: "dark" | "light" | null;
  pref_hosts_page_size: number | null;
  pref_show_active_scans_banner: boolean;
  pref_default_scanner_agent_id: string | null;
  pref_timezone: string | null;
  pref_time_format: "h12" | "h24" | null;
  pref_accent_color: "green" | "orange" | "blue" | null;
}

// Shared shape returned from /auth/login, /auth/login/verify-totp,
// /auth/me, and PATCH /auth/preferences, so the frontend never has to
// reconcile two different representations of the same thing.
function toPreferences(row: PreferenceColumns) {
  return {
    theme: row.pref_theme,
    hostsPageSize: row.pref_hosts_page_size,
    showActiveScansBanner: row.pref_show_active_scans_banner,
    defaultScannerAgentId: row.pref_default_scanner_agent_id,
    timezone: row.pref_timezone,
    timeFormat: row.pref_time_format,
    accentColor: row.pref_accent_color,
  };
}

// Node's own Intl (same engine the frontend runs in) already ships the
// full IANA tz database - reusing it here means the accepted values can
// never drift from what Intl.DateTimeFormat itself will actually accept
// at render time, without hand-maintaining a separate list. "UTC" is
// added explicitly: Intl.supportedValuesOf("timeZone") only enumerates
// canonical IANA zone identifiers, and "UTC" isn't one (confirmed by
// testing - the list has no "UTC"/"GMT"/"Etc/*" entries at all), even
// though Intl.DateTimeFormat itself accepts "UTC" as a timeZone value
// just fine. Worth special-casing since it's likely the single most
// requested option for this kind of tool.
const VALID_TIMEZONES = new Set([...Intl.supportedValuesOf("timeZone"), "UTC"]);

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

// Shared by the no-2FA login path and the verify-totp path below - both end
// up here once the account's identity is fully confirmed. Regenerates the
// session (rotates the session id on this privilege change, and - on the
// verify-totp path - drops the pendingTotpUserId set by the first step)
// before writing the authenticated fields.
function finishLogin(
  req: Request,
  res: Response,
  user: { id: number; username: string; role: string; totp_enabled: boolean; scannerAgentIds: string[] } & PreferenceColumns,
  requireAdminTotp: boolean
) {
  req.session.regenerate(async (err) => {
    if (err) {
      res.status(500).json({ error: "login failed" });
      return;
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    // Admins are always unrestricted regardless of any (normally
    // impossible) assignment row; everyone else with zero assignment rows
    // is also unrestricted - see auth/scannerScope.ts.
    req.session.allowedScannerAgentIds =
      user.role === "admin" || user.scannerAgentIds.length === 0 ? undefined : user.scannerAgentIds;
    logger.info({ event: "auth.login_success", username: user.username, source_ip: req.ip });
    recordAudit("auth.login_success", user.username, req.ip);
    // Best-effort, like recordAudit above - a failed write here must not
    // fail the login itself.
    try {
      await db.updateTable("users").set({ last_login_at: new Date().toISOString() }).where("id", "=", user.id).execute();
    } catch (updateErr) {
      logger.warn({ event: "auth.last_login_update_failed", username: user.username, err: updateErr instanceof Error ? updateErr.message : String(updateErr) });
    }
    res.json({
      username: user.username,
      role: user.role,
      version: VERSION,
      preferences: toPreferences(user),
      totpSetupRequired: computeTotpSetupRequired(user.role, user.totp_enabled, requireAdminTotp),
    });
  });
}

// An admin account without 2FA enabled, while an admin (any admin - there's
// no separate "super admin" tier) has turned on the Settings page's
// "require 2FA for all admins" toggle - see settings/appSettings.ts. Only
// ever true for role "admin": the toggle deliberately only ever governs
// admin accounts (the highest-privilege role), not operator/user.
function computeTotpSetupRequired(role: string, totpEnabled: boolean, requireAdminTotp: boolean): boolean {
  return role === "admin" && requireAdminTotp && !totpEnabled;
}

authRouter.post("/login", asyncHandler(async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "username and password are required" });
    return;
  }
  const { username, password } = parsed.data;

  const ipKey = `ip:${req.ip}`;
  const userKey = `user:${username}`;
  if (isLockedOut(ipKey) || isLockedOut(userKey)) {
    logger.warn({ event: "auth.login_locked_out", username, source_ip: req.ip });
    recordAudit("auth.login_locked_out", username, req.ip);
    res.status(429).json({ error: "too many failed login attempts, try again in 15 minutes" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select([
      "id",
      "username",
      "password_hash",
      "role",
      "totp_enabled",
      "pref_theme",
      "pref_hosts_page_size",
      "pref_show_active_scans_banner",
      "pref_default_scanner_agent_id",
      "pref_timezone",
      "pref_time_format",
      "pref_accent_color",
    ])
    .where("username", "=", username)
    .executeTakeFirst();

  const valid = user ? await verifyPassword(password, user.password_hash) : false;
  if (!user || !valid) {
    recordFailure(ipKey);
    recordFailure(userKey);
    logger.warn({ event: "auth.login_failed", username, source_ip: req.ip });
    await recordAudit("auth.login_failed", username, req.ip);
    res.status(401).json({ error: "invalid credentials" });
    return;
  }

  recordSuccess(ipKey);
  recordSuccess(userKey);

  const scannerAgentIds =
    user.role === "admin"
      ? []
      : (await db.selectFrom("user_scanner_agents").select("scanner_agent_id").where("user_id", "=", user.id).execute()).map(
          (r) => r.scanner_agent_id
        );

  if (user.totp_enabled) {
    req.session.regenerate((err) => {
      if (err) {
        res.status(500).json({ error: "login failed" });
        return;
      }
      req.session.pendingTotpUserId = user.id;
      logger.info({ event: "auth.login_password_ok_awaiting_totp", username: user.username, source_ip: req.ip });
      res.json({ requiresTotp: true });
    });
    return;
  }

  const { requireAdminTotp } = await getAppSettings();
  finishLogin(req, res, { ...user, scannerAgentIds }, requireAdminTotp);
}));

const verifyTotpSchema = z.object({ code: z.string().min(1) });

authRouter.post("/login/verify-totp", asyncHandler(async (req, res) => {
  const pendingUserId = req.session.pendingTotpUserId;
  if (!pendingUserId) {
    res.status(400).json({ error: "no login is awaiting a 2FA code" });
    return;
  }
  const parsed = verifyTotpSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "code is required" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select([
      "id",
      "username",
      "role",
      "totp_secret",
      "totp_enabled",
      "totp_recovery_codes",
      "pref_theme",
      "pref_hosts_page_size",
      "pref_show_active_scans_banner",
      "pref_default_scanner_agent_id",
      "pref_timezone",
      "pref_time_format",
      "pref_accent_color",
    ])
    .where("id", "=", pendingUserId)
    .executeTakeFirst();

  // 2FA could have been disabled (by an admin reset, or by the user in
  // another tab) between the password step and this one - treat that the
  // same as an invalid session rather than crashing on a null secret.
  if (!user || !user.totp_enabled || !user.totp_secret) {
    req.session.pendingTotpUserId = undefined;
    res.status(400).json({ error: "no login is awaiting a 2FA code" });
    return;
  }

  const ipKey = `ip:${req.ip}`;
  const totpKey = `totp:${user.username}`;
  if (isLockedOut(ipKey) || isLockedOut(totpKey)) {
    logger.warn({ event: "auth.totp_locked_out", username: user.username, source_ip: req.ip });
    recordAudit("auth.totp_locked_out", user.username, req.ip);
    res.status(429).json({ error: "too many failed 2FA attempts, try again in 15 minutes" });
    return;
  }

  const code = parsed.data.code.trim();
  let ok = verifyToken(user.totp_secret, code);
  let usedRecoveryCode = false;
  let remainingRecoveryCodes = 0;

  if (!ok && user.totp_recovery_codes && user.totp_recovery_codes.length > 0) {
    const candidateHash = hashApiKey(code.toLowerCase());
    const remaining = user.totp_recovery_codes.filter((h) => h !== candidateHash);
    if (remaining.length !== user.totp_recovery_codes.length) {
      ok = true;
      usedRecoveryCode = true;
      remainingRecoveryCodes = remaining.length;
      await db.updateTable("users").set({ totp_recovery_codes: remaining }).where("id", "=", user.id).execute();
    }
  }

  if (!ok) {
    recordFailure(ipKey);
    recordFailure(totpKey);
    logger.warn({ event: "auth.totp_failed", username: user.username, source_ip: req.ip });
    await recordAudit("auth.totp_failed", user.username, req.ip);
    res.status(401).json({ error: "invalid code" });
    return;
  }

  recordSuccess(ipKey);
  recordSuccess(totpKey);
  if (usedRecoveryCode) {
    logger.info({ event: "auth.totp_recovery_code_used", username: user.username, source_ip: req.ip });
    recordAudit("auth.totp_recovery_code_used", user.username, req.ip, {
      remaining_codes: remainingRecoveryCodes,
    });
  }

  const scannerAgentIds =
    user.role === "admin"
      ? []
      : (await db.selectFrom("user_scanner_agents").select("scanner_agent_id").where("user_id", "=", user.id).execute()).map(
          (r) => r.scanner_agent_id
        );

  const { requireAdminTotp } = await getAppSettings();
  finishLogin(req, res, { ...user, scannerAgentIds }, requireAdminTotp);
}));

authRouter.post("/logout", (req, res) => {
  const username = req.session.username;
  req.session.destroy(() => {
    logger.info({ event: "auth.logout", username, source_ip: req.ip });
    recordAudit("auth.logout", username, req.ip);
    res.clearCookie("connect.sid");
    res.status(204).end();
  });
});

authRouter.get("/me", requireAuth, asyncHandler(async (req, res) => {
  const user = await db
    .selectFrom("users")
    .select([
      "totp_enabled",
      "pref_theme",
      "pref_hosts_page_size",
      "pref_show_active_scans_banner",
      "pref_default_scanner_agent_id",
      "pref_timezone",
      "pref_time_format",
      "pref_accent_color",
    ])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  const { requireAdminTotp } = await getAppSettings();
  res.json({
    username: req.session.username,
    role: req.session.role,
    version: VERSION,
    preferences: toPreferences(user),
    totpSetupRequired: computeTotpSetupRequired(req.session.role!, user.totp_enabled, requireAdminTotp),
  });
}));

const preferencesSchema = z.object({
  theme: z.enum(["dark", "light"]).nullable().optional(),
  hostsPageSize: z.number().int().min(1).max(200).nullable().optional(),
  showActiveScansBanner: z.boolean().optional(),
  defaultScannerAgentId: z.string().uuid().nullable().optional(),
  timezone: z.string().nullable().optional(),
  timeFormat: z.enum(["h12", "h24"]).nullable().optional(),
  accentColor: z.enum(["green", "orange", "blue"]).nullable().optional(),
});

// Partial update, PATCH-style - a field absent from the request body is
// left untouched, while an explicit `null` clears it back to "no
// override" (falls back to the built-in default - see toPreferences).
// Distinguishing "absent" from "null" needs the raw body, since zod's
// parsed output can't tell "the client omitted this" apart from "this
// optional field happens to be undefined."
authRouter.patch("/preferences", requireAuth, asyncHandler(async (req, res) => {
  const parsed = preferencesSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  if (parsed.data.defaultScannerAgentId) {
    const agent = await db
      .selectFrom("scanner_agents")
      .select(["id"])
      .where("id", "=", parsed.data.defaultScannerAgentId)
      .executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scanner agent not found" });
      return;
    }
  }

  if (parsed.data.timezone && !VALID_TIMEZONES.has(parsed.data.timezone)) {
    res.status(400).json({ error: "unknown timezone" });
    return;
  }

  const updates: Record<string, unknown> = {};
  if ("theme" in req.body) updates.pref_theme = parsed.data.theme ?? null;
  if ("hostsPageSize" in req.body) updates.pref_hosts_page_size = parsed.data.hostsPageSize ?? null;
  if ("showActiveScansBanner" in req.body) updates.pref_show_active_scans_banner = parsed.data.showActiveScansBanner;
  if ("defaultScannerAgentId" in req.body) updates.pref_default_scanner_agent_id = parsed.data.defaultScannerAgentId ?? null;
  if ("timezone" in req.body) updates.pref_timezone = parsed.data.timezone ?? null;
  if ("timeFormat" in req.body) updates.pref_time_format = parsed.data.timeFormat ?? null;
  if ("accentColor" in req.body) updates.pref_accent_color = parsed.data.accentColor ?? null;

  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: "no preference fields provided" });
    return;
  }

  const user = await db
    .updateTable("users")
    .set(updates)
    .where("id", "=", req.session.userId!)
    .returning([
      "pref_theme",
      "pref_hosts_page_size",
      "pref_show_active_scans_banner",
      "pref_default_scanner_agent_id",
      "pref_timezone",
      "pref_time_format",
      "pref_accent_color",
    ])
    .executeTakeFirstOrThrow();

  res.json(toPreferences(user));
}));

// ---------------------------------------------------------------------
// Self-service 2FA management - a user can only ever set this up for
// their own account (it requires scanning a QR with their own device),
// so all of these are requireAuth rather than requireAdmin. An admin's
// only lever here is the separate reset endpoint in users/routes.ts, for
// when someone loses their device.
// ---------------------------------------------------------------------

authRouter.get("/2fa/status", requireAuth, asyncHandler(async (req, res) => {
  const user = await db
    .selectFrom("users")
    .select(["totp_enabled"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  res.json({ enabled: user.totp_enabled });
}));

authRouter.post("/2fa/setup", requireAuth, asyncHandler(async (req, res) => {
  const user = await db
    .selectFrom("users")
    .select(["username", "totp_enabled"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  if (user.totp_enabled) {
    res.status(409).json({ error: "2FA is already enabled - disable it first to set up a new device" });
    return;
  }

  // Not enabled until /confirm validates a real code from it - stored here
  // only so /confirm has something to check against. Re-calling /setup
  // (e.g. the user re-scans) simply overwrites this pending secret, since
  // nothing depends on the old one until it's confirmed.
  const secret = generateSecret();
  await db.updateTable("users").set({ totp_secret: secret }).where("id", "=", req.session.userId!).execute();

  res.json({
    secret,
    otpauthUrl: buildOtpauthUrl(secret, user.username),
    qrCodeDataUrl: await qrcode.toDataURL(buildOtpauthUrl(secret, user.username)),
  });
}));

authRouter.post("/2fa/confirm", requireAuth, asyncHandler(async (req, res) => {
  const parsed = verifyTotpSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "code is required" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select(["username", "totp_secret", "totp_enabled"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  if (user.totp_enabled) {
    res.status(409).json({ error: "2FA is already enabled" });
    return;
  }
  if (!user.totp_secret) {
    res.status(400).json({ error: "call /auth/2fa/setup first" });
    return;
  }

  const confirmIpKey = `ip:${req.ip}`;
  const confirmKey = `totpsetup:${user.username}`;
  if (isLockedOut(confirmIpKey) || isLockedOut(confirmKey)) {
    res.status(429).json({ error: "too many failed 2FA attempts, try again in 15 minutes" });
    return;
  }
  if (!verifyToken(user.totp_secret, parsed.data.code)) {
    recordFailure(confirmIpKey);
    recordFailure(confirmKey);
    res.status(400).json({ error: "invalid code" });
    return;
  }
  recordSuccess(confirmIpKey);
  recordSuccess(confirmKey);

  const recoveryCodes = generateRecoveryCodes();
  await db
    .updateTable("users")
    .set({ totp_enabled: true, totp_recovery_codes: recoveryCodes.map((c) => hashApiKey(c)) })
    .where("id", "=", req.session.userId!)
    .execute();

  logger.info({ event: "auth.totp_enabled", username: user.username, source_ip: req.ip });
  recordAudit("auth.totp_enabled", user.username, req.ip);

  res.json({ recoveryCodes });
}));

const disable2faSchema = z.object({ password: z.string().min(1) });

authRouter.post("/2fa/disable", requireAuth, asyncHandler(async (req, res) => {
  const parsed = disable2faSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "password is required" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select(["username", "password_hash", "totp_enabled"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  if (!user.totp_enabled) {
    res.status(409).json({ error: "2FA is not enabled" });
    return;
  }

  const disableIpKey = `ip:${req.ip}`;
  const disableKey = `disable2fa:${user.username}`;
  if (isLockedOut(disableIpKey) || isLockedOut(disableKey)) {
    res.status(429).json({ error: "too many failed attempts, try again in 15 minutes" });
    return;
  }
  if (!(await verifyPassword(parsed.data.password, user.password_hash))) {
    recordFailure(disableIpKey);
    recordFailure(disableKey);
    res.status(401).json({ error: "invalid password" });
    return;
  }
  recordSuccess(disableIpKey);
  recordSuccess(disableKey);

  await db
    .updateTable("users")
    .set({ totp_enabled: false, totp_secret: null, totp_recovery_codes: null })
    .where("id", "=", req.session.userId!)
    .execute();

  logger.info({ event: "auth.totp_disabled", username: user.username, source_ip: req.ip });
  recordAudit("auth.totp_disabled", user.username, req.ip);

  res.status(204).end();
}));

// Same minimum as createUserSchema's - deliberately not stricter here, so
// a policy an admin could satisfy when creating the account can't become
// unsatisfiable when the owner later tries to change it.
const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
});

// Until this existed there was no way to change a password at all, at any
// tier - password_hash was only ever written once, at account creation.
// A shared or leaked credential could only be remediated by deleting the
// account outright, which also threw away its 2FA enrolment and scanner
// assignments.
//
// Self-service and requiring the current password (not merely a live
// session), same reasoning as /2fa/disable directly above: a session
// alone isn't proof the person at the keyboard is still the account
// owner, which is exactly the case this endpoint has to defend against.
authRouter.post("/password", requireAuth, asyncHandler(async (req, res) => {
  const parsed = changePasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "current password and a new password of at least 8 characters are required" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select(["username", "password_hash"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();

  // Its own key prefix rather than sharing the login counter - guessing
  // an already-authenticated session's current password is a different
  // attack from guessing a login, and conflating them would let one lock
  // out the other.
  const ipKey = `ip:${req.ip}`;
  const userKey = `changepw:${user.username}`;
  if (isLockedOut(ipKey) || isLockedOut(userKey)) {
    res.status(429).json({ error: "too many failed attempts, try again in 15 minutes" });
    return;
  }
  if (!(await verifyPassword(parsed.data.currentPassword, user.password_hash))) {
    recordFailure(ipKey);
    recordFailure(userKey);
    logger.warn({ event: "auth.password_change_failed", username: user.username, source_ip: req.ip });
    res.status(401).json({ error: "current password is incorrect" });
    return;
  }
  recordSuccess(ipKey);
  recordSuccess(userKey);

  if (parsed.data.newPassword === parsed.data.currentPassword) {
    res.status(400).json({ error: "the new password must differ from the current one" });
    return;
  }

  await db
    .updateTable("users")
    .set({ password_hash: await hashPassword(parsed.data.newPassword) })
    .where("id", "=", req.session.userId!)
    .execute();

  // Every *other* session for this account is terminated - a password
  // change is exactly when someone wants sessions they don't control to
  // stop working. This one is kept: the caller just proved they know the
  // current password, so signing them out would be pure friction.
  const revoked = await revokeUserSessions(req.session.userId!, req.sessionID);

  logger.info({ event: "auth.password_changed", username: user.username, source_ip: req.ip, sessions_revoked: revoked });
  recordAudit("auth.password_changed", user.username, req.ip);

  res.status(204).end();
}));

// "Sign out everywhere else" - the standalone counterpart to the implicit
// revocation a password change already performs. Wanted on its own
// because the usual trigger (a laptop left signed in somewhere, a shared
// browser) is not a reason to change a password, and making people change
// one to get the side effect is how you end up with worse passwords.
authRouter.post("/sessions/revoke-others", requireAuth, asyncHandler(async (req, res) => {
  const revoked = await revokeUserSessions(req.session.userId!, req.sessionID);
  logger.info({ event: "auth.sessions_revoked", username: req.session.username, count: revoked, source_ip: req.ip });
  recordAudit("auth.sessions_revoked", req.session.username, req.ip, { count: revoked });
  res.json({ revoked });
}));

authRouter.post("/2fa/recovery-codes/regenerate", requireAuth, asyncHandler(async (req, res) => {
  const parsed = verifyTotpSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "code is required" });
    return;
  }

  const user = await db
    .selectFrom("users")
    .select(["username", "totp_secret", "totp_enabled"])
    .where("id", "=", req.session.userId!)
    .executeTakeFirstOrThrow();
  if (!user.totp_enabled || !user.totp_secret) {
    res.status(409).json({ error: "2FA is not enabled" });
    return;
  }

  const regenIpKey = `ip:${req.ip}`;
  const regenKey = `totpregen:${user.username}`;
  if (isLockedOut(regenIpKey) || isLockedOut(regenKey)) {
    res.status(429).json({ error: "too many failed 2FA attempts, try again in 15 minutes" });
    return;
  }
  if (!verifyToken(user.totp_secret, parsed.data.code)) {
    recordFailure(regenIpKey);
    recordFailure(regenKey);
    res.status(400).json({ error: "invalid code" });
    return;
  }
  recordSuccess(regenIpKey);
  recordSuccess(regenKey);

  const recoveryCodes = generateRecoveryCodes();
  await db
    .updateTable("users")
    .set({ totp_recovery_codes: recoveryCodes.map((c) => hashApiKey(c)) })
    .where("id", "=", req.session.userId!)
    .execute();

  logger.info({ event: "auth.totp_recovery_codes_regenerated", username: user.username, source_ip: req.ip });
  recordAudit("auth.totp_recovery_codes_regenerated", user.username, req.ip);

  res.json({ recoveryCodes });
}));
