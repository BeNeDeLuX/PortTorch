import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { buildTeamsAdaptiveCardBody, recordDelivery, WebhookEvent } from "./dispatch";
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
  "auth.account_locked",
  "scan.completed",
  "scan.stale",
  "scanner.update_failed",
  "scan_queue.backlog",
  "nuclei.finding",
  "scanner.offline",
  "host.disappeared",
  "port.closed",
  "network.coverage_stale",
  "ssh_key.shared",
  "ca_certificate.expiring_soon",
];
const uuidSchema = z.string().uuid();
const WEBHOOK_COLUMNS = [
  "id",
  "name",
  "channel_type",
  "url",
  "email_to",
  "enabled",
  "events",
  "created_at",
  "filter_scanner_agent_ids",
  "filter_tags",
  "min_severity",
  "verify_tls",
] as const;

// The one list of event names, served rather than repeated. It had been
// copied three times - here, in the create schema's own enum, and again
// in the dashboard's own ALL_EVENTS - and all three had drifted: six of
// the fifteen events could not be subscribed to from the dashboard at
// all, and two more were rejected by the schema if you tried through the
// API. They fired the whole time, with nowhere to go.
//
// Registered before "/:id/deliveries" so "events" isn't read as an id.
webhooksRouter.get("/events", asyncHandler(async (_req, res) => {
  res.json(EVENTS);
}));

webhooksRouter.get("/", asyncHandler(async (_req, res) => {
  const webhooks = await db
    .selectFrom("webhooks")
    .select(WEBHOOK_COLUMNS)
    .orderBy("created_at", "desc")
    .execute();
  res.json(webhooks);
}));

// The most recent deliveries for one webhook (see dispatch.ts's
// recordDelivery, which trims this to MAX_DELIVERIES_PER_WEBHOOK rows at
// insert time) - same read access level as the webhook list itself
// (requireAuth only, not requireAdmin), since seeing whether a webhook is
// actually working isn't more sensitive than seeing that it exists.
webhooksRouter.get("/:id/deliveries", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid webhook id" });
    return;
  }
  const deliveries = await db
    .selectFrom("webhook_deliveries")
    .select(["id", "event", "success", "status_code", "error", "created_at"])
    .where("webhook_id", "=", req.params.id)
    .orderBy("created_at", "desc")
    .execute();
  res.json(deliveries);
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
    // Derived from EVENTS rather than repeated: the two lists had already
    // drifted once - network.coverage_stale and ssh_key.shared were
    // offered by the API that feeds the picker but rejected by this
    // schema, so subscribing to either failed with a 400 that named no
    // cause.
    events: z.array(z.enum(EVENTS as [WebhookEvent, ...WebhookEvent[]])).min(1),
    // All three narrow the channel; empty/omitted means "everything", so
    // this never changes what an existing channel receives. See
    // webhooks/filter.ts for why host-based filters only ever narrow
    // host-scoped events.
    filterScannerAgentIds: z.array(z.string().uuid()).default([]),
    filterTags: z.array(z.string().trim().min(1)).default([]),
    minSeverity: z.enum(["info", "low", "medium", "high", "critical"]).nullish(),
    verifyTls: z.boolean().default(true),
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
  const { name, channelType, url, emailTo, events, filterScannerAgentIds, filterTags, minSeverity, verifyTls } =
    parsed.data;

  const webhook = await db
    .insertInto("webhooks")
    .values({
      name,
      channel_type: channelType,
      url: channelType === "email" ? null : url!,
      email_to: channelType === "email" ? emailTo! : null,
      events,
      filter_scanner_agent_ids: filterScannerAgentIds,
      filter_tags: filterTags,
      min_severity: minSeverity ?? null,
      verify_tls: verifyTls,
    })
    .returning(WEBHOOK_COLUMNS)
    .executeTakeFirstOrThrow();

  logger.info({
    event: "webhook.created",
    webhook_id: webhook.id,
    name: webhook.name,
    channel_type: webhook.channel_type,
    filter_scanner_agent_ids: filterScannerAgentIds,
    filter_tags: filterTags,
    min_severity: minSeverity ?? null,
    created_by: req.session.username,
  });
  recordAudit("webhook.created", req.session.username, req.ip, { webhook_id: webhook.id, name: webhook.name, channel_type: webhook.channel_type });

  res.status(201).json(webhook);
}));

// Every field is optional and only what is present is written - a
// genuine partial update, so the existing "just flip enabled" callers
// keep working unchanged.
//
// This used to accept `enabled` alone, which meant adjusting a filter, a
// target URL or the event list required deleting the channel and creating
// it again - and webhook_deliveries hangs off it with ON DELETE CASCADE,
// so that also threw away the delivery history, which is the only record
// of whether the channel was ever working.
const updateWebhookSchema = z.object({
  enabled: z.boolean().optional(),
  name: z.string().trim().min(1).max(100).optional(),
  url: z.string().url().optional(),
  emailTo: emailListSchema.optional(),
  events: z.array(z.enum(EVENTS as [WebhookEvent, ...WebhookEvent[]])).min(1).optional(),
  filterScannerAgentIds: z.array(z.string().uuid()).optional(),
  filterTags: z.array(z.string().trim().min(1)).optional(),
  // Explicit null clears the minimum; omitted leaves it alone. The two
  // have to stay distinguishable or a channel's severity floor could
  // never be removed once set.
  minSeverity: z.enum(["info", "low", "medium", "high", "critical"]).nullable().optional(),
  verifyTls: z.boolean().optional(),
});

webhooksRouter.patch("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid webhook id" });
    return;
  }
  const parsed = updateWebhookSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const d = parsed.data;
  const patch = {
    ...(d.enabled !== undefined ? { enabled: d.enabled } : {}),
    ...(d.name !== undefined ? { name: d.name } : {}),
    ...(d.url !== undefined ? { url: d.url } : {}),
    ...(d.emailTo !== undefined ? { email_to: d.emailTo } : {}),
    ...(d.events !== undefined ? { events: d.events } : {}),
    ...(d.filterScannerAgentIds !== undefined ? { filter_scanner_agent_ids: d.filterScannerAgentIds } : {}),
    ...(d.filterTags !== undefined ? { filter_tags: d.filterTags } : {}),
    ...("minSeverity" in req.body ? { min_severity: d.minSeverity ?? null } : {}),
    ...(d.verifyTls !== undefined ? { verify_tls: d.verifyTls } : {}),
  };
  if (Object.keys(patch).length === 0) {
    res.status(400).json({ error: "nothing to update" });
    return;
  }

  const updated = await db
    .updateTable("webhooks")
    .set(patch)
    .where("id", "=", req.params.id)
    .returning(WEBHOOK_COLUMNS)
    .executeTakeFirst();

  if (!updated) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }

  // The url/email_to pairing is enforced by a table CHECK constraint, so
  // a patch that would break it fails loudly rather than half-applying -
  // no separate validation needed here.
  logger.info({
    event: "webhook.updated",
    webhook_id: updated.id,
    name: updated.name,
    changed: Object.keys(patch),
    updated_by: req.session.username,
  });
  recordAudit("webhook.updated", req.session.username, req.ip, {
    webhook_id: updated.id,
    changed: Object.keys(patch),
  });
  res.json(updated);
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
  const webhookId = req.params.id as string;
  const webhook = await db.selectFrom("webhooks").select(["channel_type", "url", "email_to"]).where("id", "=", webhookId).executeTakeFirst();
  if (!webhook) {
    res.status(404).json({ error: "webhook not found" });
    return;
  }

  if (webhook.channel_type === "email") {
    try {
      await sendEmailAlert(webhook.email_to!, "PortTorch test notification", "PortTorch test notification");
      await recordDelivery(webhookId, "test", true, null, null);
      res.json({ ok: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await recordDelivery(webhookId, "test", false, null, message);
      res.json({ ok: false, error: message });
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
    await recordDelivery(webhookId, "test", testResponse.ok, testResponse.status, null);
    res.json({ ok: testResponse.ok, status: testResponse.status });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await recordDelivery(webhookId, "test", false, null, message);
    res.json({ ok: false, error: message });
  }
}));

export { EVENTS as WEBHOOK_EVENTS };
