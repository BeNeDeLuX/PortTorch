import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { hashApiKey } from "../ingest/apiKeyAuth";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";

// Admin-only, like scanner agents. What a token may do is no longer
// fixed: scope decides whether it can only read or can also trigger and
// cancel scans, and scannerAgentIds can confine it to one segment's
// results, mirroring a dashboard user's own assignment.
export const apiTokensRouter = Router();
apiTokensRouter.use(requireAuth, requireAdmin);

apiTokensRouter.get("/", asyncHandler(async (_req, res) => {
  const tokens = await db
    .selectFrom("api_tokens")
    .select(["id", "name", "last_used_at", "created_at", "revoked_at", "expires_at", "scope", "scanner_agent_ids"])
    .orderBy("created_at", "desc")
    .execute();
  res.json(tokens);
}));

// expiresAt is optional (omitted/undefined - and null, sent by a client
// explicitly choosing "never" - both mean no expiry) and, when present,
// must be a real future date - a token created already-expired would be
// useless, so this is rejected at creation time rather than silently
// accepted.
const createTokenSchema = z.object({
  name: z.string().trim().min(1).max(100),
  expiresAt: z
    .string()
    .refine((v) => !Number.isNaN(new Date(v).getTime()) && new Date(v).getTime() > Date.now(), {
      message: "expiresAt must be a valid date in the future",
    })
    .nullable()
    .optional(),
  // Defaults to the least-privileged option when omitted. The *column*
  // defaults to read_write instead, so tokens created before this existed
  // keep working - the two differ deliberately.
  scope: z.enum(["read", "read_write"]).default("read"),
  // Empty (or omitted) = every scanner, same convention as a user's own
  // assignment rows.
  scannerAgentIds: z.array(z.string().uuid()).default([]),
});

apiTokensRouter.post("/", asyncHandler(async (req, res) => {
  const parsed = createTokenSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const token = crypto.randomBytes(32).toString("hex");
  const created = await db
    .insertInto("api_tokens")
    .values({
      name: parsed.data.name,
      token_hash: hashApiKey(token),
      created_by: req.session.username!,
      expires_at: parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : null,
      scope: parsed.data.scope,
      scanner_agent_ids: parsed.data.scannerAgentIds,
    })
    .returning(["id", "name", "created_at", "expires_at", "scope", "scanner_agent_ids"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "api_token.created",
    api_token_id: created.id,
    name: created.name,
    scope: created.scope,
    scanner_agent_ids: created.scanner_agent_ids,
    created_by: req.session.username,
  });
  recordAudit("api_token.created", req.session.username, req.ip, {
    api_token_id: created.id,
    name: created.name,
    scope: created.scope,
    scanner_agent_ids: created.scanner_agent_ids,
  });

  // The plaintext token is only returned once, at creation time.
  res.status(201).json({ ...created, token });
}));

const uuidSchema = z.string().uuid();

apiTokensRouter.post("/:id/revoke", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid api token id" });
    return;
  }

  const result = await db
    .updateTable("api_tokens")
    .set({ revoked_at: new Date() })
    .where("id", "=", req.params.id)
    .where("revoked_at", "is", null)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    res.status(404).json({ error: "api token not found or already revoked" });
    return;
  }

  logger.info({ event: "api_token.revoked", api_token_id: req.params.id, revoked_by: req.session.username });
  recordAudit("api_token.revoked", req.session.username, req.ip, { api_token_id: req.params.id });

  res.status(204).end();
}));
