import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAdmin } from "../auth/middleware";
import { hashPassword } from "../auth/password";
import { revokeUserSessions } from "../auth/sessions";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { singleParam } from "../lib/reqParams";

export const usersRouter = Router();
usersRouter.use(requireAdmin);

usersRouter.get("/", asyncHandler(async (_req, res) => {
  const users = await db
    .selectFrom("users")
    .select(["id", "username", "role", "created_at", "last_login_at", "totp_enabled"])
    .orderBy("created_at", "desc")
    .execute();

  // Batched rather than one query per user - same "load everything, group
  // in a Map" idiom as digest/routes.ts's scannerByScanJobId.
  const assignments = await db.selectFrom("user_scanner_agents").select(["user_id", "scanner_agent_id"]).execute();
  const scannerIdsByUser = new Map<number, string[]>();
  for (const a of assignments) {
    scannerIdsByUser.set(a.user_id, [...(scannerIdsByUser.get(a.user_id) ?? []), a.scanner_agent_id]);
  }

  res.json(users.map((u) => ({ ...u, scannerAgentIds: scannerIdsByUser.get(u.id) ?? [] })));
}));

const createUserSchema = z.object({
  username: z.string().trim().min(1).max(64),
  password: z.string().min(8),
  role: z.enum(["admin", "operator", "user"]).default("user"),
  // Restricts this user to only see these scanners' results (see
  // auth/scannerScope.ts) - omitted or empty means unrestricted. Ignored
  // for an admin-role account, since admins are always unrestricted.
  scannerAgentIds: z.array(z.string().uuid()).optional(),
});

async function validateScannerAgentIds(ids: string[]): Promise<boolean> {
  if (ids.length === 0) return true;
  const found = await db.selectFrom("scanner_agents").select(["id"]).where("id", "in", ids).execute();
  return found.length === new Set(ids).size;
}

usersRouter.post("/", asyncHandler(async (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const existing = await db
    .selectFrom("users")
    .select(["id"])
    .where("username", "=", parsed.data.username)
    .executeTakeFirst();
  if (existing) {
    res.status(409).json({ error: "username already taken" });
    return;
  }

  // Admins are always unrestricted - silently drop any ids sent alongside
  // an admin-role creation rather than rejecting a harmless combination.
  const scannerAgentIds = parsed.data.role === "admin" ? [] : (parsed.data.scannerAgentIds ?? []);
  if (!(await validateScannerAgentIds(scannerAgentIds))) {
    res.status(400).json({ error: "unknown scanner agent id" });
    return;
  }

  const passwordHash = await hashPassword(parsed.data.password);
  const user = await db.transaction().execute(async (trx) => {
    const inserted = await trx
      .insertInto("users")
      .values({ username: parsed.data.username, password_hash: passwordHash, role: parsed.data.role })
      .returning(["id", "username", "role", "created_at", "last_login_at", "totp_enabled"])
      .executeTakeFirstOrThrow();
    if (scannerAgentIds.length > 0) {
      await trx
        .insertInto("user_scanner_agents")
        .values(scannerAgentIds.map((scanner_agent_id) => ({ user_id: inserted.id, scanner_agent_id })))
        .execute();
    }
    return inserted;
  });

  logger.info({
    event: "user.created",
    user_id: user.id,
    username: user.username,
    role: user.role,
    scanner_agent_ids: scannerAgentIds,
    created_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("user.created", req.session.username, req.ip, {
    user_id: user.id,
    username: user.username,
    role: user.role,
    scanner_agent_ids: scannerAgentIds,
  });

  res.status(201).json({ ...user, scannerAgentIds });
}));

const setScannerAgentsSchema = z.object({ scannerAgentIds: z.array(z.string().uuid()) });

// Replace-all-or-nothing: the caller sends the full desired set (empty
// array clears the restriction back to unrestricted), rather than an
// incremental add/remove - simpler to reason about from the frontend's
// checkbox-list UI, which always holds the full current selection anyway.
usersRouter.patch("/:id/scanner-agents", asyncHandler(async (req, res) => {
  const id = parseInt(singleParam(req.params.id), 10);
  if (Number.isNaN(id)) {
    res.status(400).json({ error: "invalid user id" });
    return;
  }
  const parsed = setScannerAgentsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const target = await db.selectFrom("users").select(["id", "role"]).where("id", "=", id).executeTakeFirst();
  if (!target) {
    res.status(404).json({ error: "user not found" });
    return;
  }
  if (target.role === "admin") {
    res.status(400).json({ error: "cannot restrict an admin account - admins always see every scanner's results" });
    return;
  }
  if (!(await validateScannerAgentIds(parsed.data.scannerAgentIds))) {
    res.status(400).json({ error: "unknown scanner agent id" });
    return;
  }

  await db.transaction().execute(async (trx) => {
    await trx.deleteFrom("user_scanner_agents").where("user_id", "=", id).execute();
    if (parsed.data.scannerAgentIds.length > 0) {
      await trx
        .insertInto("user_scanner_agents")
        .values(parsed.data.scannerAgentIds.map((scanner_agent_id) => ({ user_id: id, scanner_agent_id })))
        .execute();
    }
  });

  logger.info({
    event: "user.scanner_access_updated",
    user_id: id,
    scanner_agent_ids: parsed.data.scannerAgentIds,
    updated_by: req.session.username,
  });
  recordAudit("user.scanner_access_updated", req.session.username, req.ip, {
    user_id: id,
    scanner_agent_ids: parsed.data.scannerAgentIds,
  });

  res.json({ scannerAgentIds: parsed.data.scannerAgentIds });
}));

usersRouter.delete("/:id", asyncHandler(async (req, res) => {
  const id = parseInt(singleParam(req.params.id), 10);
  if (Number.isNaN(id)) {
    res.status(400).json({ error: "invalid user id" });
    return;
  }
  if (id === req.session.userId) {
    res.status(400).json({ error: "cannot delete your own account" });
    return;
  }

  const target = await db.selectFrom("users").select(["role"]).where("id", "=", id).executeTakeFirst();
  if (!target) {
    res.status(404).json({ error: "user not found" });
    return;
  }
  if (target.role === "admin") {
    const adminCount = await db
      .selectFrom("users")
      .select(({ fn }) => fn.countAll().as("count"))
      .where("role", "=", "admin")
      .executeTakeFirstOrThrow();
    if (Number(adminCount.count) <= 1) {
      res.status(400).json({ error: "cannot delete the last admin account" });
      return;
    }
  }

  await db.deleteFrom("users").where("id", "=", id).execute();

  // requireAuth only checks that session.userId is set - it never
  // revalidates against the users table - so without this a deleted
  // account stays fully usable until its cookie expires, up to 12 hours
  // later. Revoking here is cheaper and more reliable than a DB lookup on
  // every authenticated request, which is the alternative fix.
  const revokedSessions = await revokeUserSessions(id);

  logger.info({
    event: "user.deleted",
    user_id: id,
    sessions_revoked: revokedSessions,
    deleted_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("user.deleted", req.session.username, req.ip, { user_id: id });

  res.status(204).end();
}));

// For when someone loses their authenticator device - 2FA setup itself is
// necessarily self-service (see auth/routes.ts), but recovering from a lost
// device isn't, so this is the one place an admin can act on another
// user's 2FA at all: turning it back off, never turning it on for them.
const setPasswordSchema = z.object({ password: z.string().min(8) });

// The recovery path for a forgotten password, and the counterpart to
// /auth/password's self-service change: without it, the only remedy was
// deleting and recreating the account, which also discards its 2FA
// enrolment and scanner assignments.
//
// Unlike the self-service route, no current password is required - the
// whole point is that nobody has it. That makes this a genuine account
// takeover primitive, which is why it's admin-only (the whole router is)
// and audited with both actor and target. It deliberately does NOT clear
// 2FA: an admin who resets a password shouldn't thereby gain the ability
// to log in as that user, and reset-2fa right below is the separate,
// separately-audited action for the genuinely-lost-device case.
usersRouter.post("/:id/password", asyncHandler(async (req, res) => {
  const id = parseInt(singleParam(req.params.id), 10);
  if (Number.isNaN(id)) {
    res.status(400).json({ error: "invalid user id" });
    return;
  }
  const parsed = setPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "a password of at least 8 characters is required" });
    return;
  }

  const target = await db.selectFrom("users").select(["username"]).where("id", "=", id).executeTakeFirst();
  if (!target) {
    res.status(404).json({ error: "user not found" });
    return;
  }

  await db
    .updateTable("users")
    .set({ password_hash: await hashPassword(parsed.data.password) })
    .where("id", "=", id)
    .execute();

  // Every session of the target account, with no exception: an admin
  // resets a password precisely when they suspect it's compromised, and
  // leaving the existing session alive would make the reset look like a
  // lockout without being one.
  const revokedSessions = await revokeUserSessions(id);

  logger.info({
    event: "user.password_reset",
    sessions_revoked: revokedSessions,
    user_id: id,
    username: target.username,
    reset_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("user.password_reset", req.session.username, req.ip, { user_id: id, username: target.username });

  res.status(204).end();
}));

usersRouter.post("/:id/reset-2fa", asyncHandler(async (req, res) => {
  const id = parseInt(singleParam(req.params.id), 10);
  if (Number.isNaN(id)) {
    res.status(400).json({ error: "invalid user id" });
    return;
  }

  const target = await db.selectFrom("users").select(["username", "totp_enabled"]).where("id", "=", id).executeTakeFirst();
  if (!target) {
    res.status(404).json({ error: "user not found" });
    return;
  }
  if (!target.totp_enabled) {
    res.status(409).json({ error: "2FA is not enabled for this user" });
    return;
  }

  await db
    .updateTable("users")
    .set({ totp_enabled: false, totp_secret: null, totp_recovery_codes: null })
    .where("id", "=", id)
    .execute();

  logger.info({
    event: "user.2fa_reset",
    user_id: id,
    username: target.username,
    reset_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("user.2fa_reset", req.session.username, req.ip, { user_id: id, username: target.username });

  res.status(204).end();
}));
