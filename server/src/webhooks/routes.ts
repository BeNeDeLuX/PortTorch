import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { buildTeamsAdaptiveCardBody, WebhookEvent } from "./dispatch";
import { sendEmailAlert } from "./email";
import { recordAudit } from "../audit/log";

export const webhooksRouter = Router();
webhooksRouter.use(requireAuth);

const EVENTS: WebhookEvent[] = [
  "host.new",
  "port.opened",
  "certificate.expiring_soon",
  "webserver_certificate.expiring_soon",
  "saved_search.match",
  "vulnerability.high_epss",
  "vulnerability.kev",
  "digest.daily",
  "scan.stale",
  "scanner.update_failed",
  "scan_queue.backlog",
];
const uuidSchema = z.string().uuid();
const WEBHOOK_COLUMNS = ["id", "name", "channel_type", "url", "email_to", "enabled", "events", "created_at"] as const;

webhooksRouter.get("/", asyncHandler(async (_req, res) => {
  const webhooks = await db
    .selectFrom("webhooks")
    .select(WEBHOOK_COLUMNS)
    .orderBy("created_at", "desc")
    .execute();
  res.json(webhooks);
}));

// Comma-joined list, same convention as every other multi-value field in
// this app - each address individually validated so a typo in one of
// several recipients is caught at creation time, not at first delivery
// failure.
const emailListSchema = z
  .string()
  .trim()
  .min(1)
  .max(1000)
  .refine((val) => val.split(",").every((addr) => z.string().trim().email().safeParse(addr.trim()).success), {
    message: "one or more email addresses are invalid",
  });

const createWebhookSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    channelType: z.enum(["webhook", "email", "teams"]).default("webhook"),
    url: z.string().url().optional(),
    emailTo: emailListSchema.optional(),
    events: z
      .array(
        z.enum([
          "host.new",
          "port.opened",
          "certificate.expiring_soon",
          "webserver_certificate.expiring_soon",
          "saved_search.match",
          "vulnerability.high_epss",
          "vulnerability.kev",
          "digest.daily",
          "scan.stale",
          "scanner.update_failed",
          "scan_queue.backlog",
        ])
      )
      .min(1),
  })
  .refine((data) => (data.channelType === "email" ? !!data.emailTo : !!data.url), {
    message: "url is required for a webhook/teams channel, emailTo is required for an email channel",
  });

webhooksRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createWebhookSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { name, channelType, url, emailTo, events } = parsed.data;

  const webhook = await db
    .insertInto("webhooks")
    .values({
      name,
      channel_type: channelType,
      url: channelType === "email" ? null : url!,
      email_to: channelType === "email" ? emailTo! : null,
      events,
    })
    .returning(WEBHOOK_COLUMNS)
    .executeTakeFirstOrThrow();

  logger.info({ event: "webhook.created", webhook_id: webhook.id, name: webhook.name, channel_type: webhook.channel_type, created_by: req.session.username });
  recordAudit("webhook.created", req.session.username, req.ip, { webhook_id: webhook.id, name: webhook.name, channel_type: webhook.channel_type });

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
  const webhook = await db.selectFrom("webhooks").select(["channel_type", "url", "email_to"]).where("id", "=", req.params.id).executeTakeFirst();
  if (!webhook) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }

  if (webhook.channel_type === "email") {
    try {
      await sendEmailAlert(webhook.email_to!, "PortTorch test notification", "PortTorch test notification");
      res.json({ ok: true });
    } catch (err) {
      res.json({ ok: false, error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }

  const testBody =
    webhook.channel_type === "teams"
      ? buildTeamsAdaptiveCardBody("PortTorch test notification", "PortTorch test notification")
      : JSON.stringify({
          text: "PortTorch test notification",
          content: "PortTorch test notification",
          event: "test",
          data: {},
          timestamp: new Date().toISOString(),
        });

  try {
    const testResponse = await fetch(webhook.url!, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: testBody,
    });
    res.json({ ok: testResponse.ok, status: testResponse.status });
  } catch (err) {
    res.json({ ok: false, error: err instanceof Error ? err.message : String(err) });
  }
}));

export { EVENTS as WEBHOOK_EVENTS };
