import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { WebhookEvent } from "./dispatch";
import { recordAudit } from "../audit/log";

export const webhooksRouter = Router();
webhooksRouter.use(requireAuth);

const EVENTS: WebhookEvent[] = ["host.new", "port.opened", "certificate.expiring_soon", "saved_search.match"];
const uuidSchema = z.string().uuid();

webhooksRouter.get("/", asyncHandler(async (_req, res) => {
  const webhooks = await db
    .selectFrom("webhooks")
    .select(["id", "name", "url", "enabled", "events", "created_at"])
    .orderBy("created_at", "desc")
    .execute();
  res.json(webhooks);
}));

const createWebhookSchema = z.object({
  name: z.string().trim().min(1).max(100),
  url: z.string().url(),
  events: z.array(z.enum(["host.new", "port.opened", "certificate.expiring_soon", "saved_search.match"])).min(1),
});

webhooksRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createWebhookSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const webhook = await db
    .insertInto("webhooks")
    .values({ name: parsed.data.name, url: parsed.data.url, events: parsed.data.events })
    .returning(["id", "name", "url", "enabled", "events", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({ event: "webhook.created", webhook_id: webhook.id, name: webhook.name, created_by: req.session.username });
  recordAudit("webhook.created", req.session.username, req.ip, { webhook_id: webhook.id, name: webhook.name });

  res.status(201).json(webhook);
}));

const updateWebhookSchema = z.object({
  enabled: z.boolean().optional(),
});

webhooksRouter.patch("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid webhook id" });
    return;
  }
  const parsed = updateWebhookSchema.safeParse(req.body);
  if (!parsed.success || parsed.data.enabled === undefined) {
    res.status(400).json({ error: "nothing to update" });
    return;
  }

  const result = await db
    .updateTable("webhooks")
    .set({ enabled: parsed.data.enabled })
    .where("id", "=", req.params.id)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }
  recordAudit("webhook.updated", req.session.username, req.ip, { webhook_id: req.params.id, enabled: parsed.data.enabled });
  res.status(204).end();
}));

webhooksRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid webhook id" });
    return;
  }
  const result = await db.deleteFrom("webhooks").where("id", "=", req.params.id).executeTakeFirst();
  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }
  logger.info({ event: "webhook.deleted", webhook_id: req.params.id, deleted_by: req.session.username });
  recordAudit("webhook.deleted", req.session.username, req.ip, { webhook_id: req.params.id });
  res.status(204).end();
}));

webhooksRouter.post("/:id/test", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid webhook id" });
    return;
  }
  const webhook = await db.selectFrom("webhooks").select(["url"]).where("id", "=", req.params.id).executeTakeFirst();
  if (!webhook) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }

  try {
    const testResponse = await fetch(webhook.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "PortTorch test notification",
        content: "PortTorch test notification",
        event: "test",
        data: {},
        timestamp: new Date().toISOString(),
      }),
    });
    res.json({ ok: testResponse.ok, status: testResponse.status });
  } catch (err) {
    res.json({ ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}));

export { EVENTS as WEBHOOK_EVENTS };
