import { db } from "../db";
import { logger } from "../logger";

export type WebhookEvent = "host.new" | "port.opened" | "certificate.expiring_soon" | "saved_search.match";

// Fire-and-forget: dispatch must never slow down or fail the request that
// triggered it (scanner ingest, in particular), so failures are only
// logged, never thrown. Sends both "text" and "content" so the same
// payload renders in Slack and Discord incoming webhooks without needing
// per-target payload shapes; "data" carries the structured fields for
// anything else consuming it directly.
export async function dispatchWebhook(event: WebhookEvent, message: string, data: Record<string, unknown>): Promise<void> {
  let hooks: Array<{ id: string; url: string; events: string[] }>;
  try {
    hooks = await db
      .selectFrom("webhooks")
      .select(["id", "url", "events"])
      .where("enabled", "=", true)
      .execute();
  } catch (err) {
    logger.warn({ event: "webhook.lookup_failed", err: err instanceof Error ? err.message : String(err) });
    return;
  }

  const targets = hooks.filter((h) => h.events.includes(event));
  const body = JSON.stringify({ text: message, content: message, event, data, timestamp: new Date().toISOString() });

  for (const hook of targets) {
    fetch(hook.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    })
      .then((res) => {
        if (!res.ok) {
          logger.warn({ event: "webhook.delivery_failed", webhook_id: hook.id, webhook_event: event, status: res.status });
        }
      })
      .catch((err) => {
        logger.warn({
          event: "webhook.delivery_failed",
          webhook_id: hook.id,
          webhook_event: event,
          error: err instanceof Error ? err.message : String(err),
        });
      });
  }
}
