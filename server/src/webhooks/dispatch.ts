import { db } from "../db";
import { logger } from "../logger";
import { sendEmailAlert } from "./email";

export type WebhookEvent =
  | "host.new"
  | "port.opened"
  | "certificate.expiring_soon"
  | "saved_search.match"
  | "vulnerability.high_epss"
  | "digest.daily";

// Plain-English subject line for an email channel - a webhook channel has
// no equivalent need, since "event"/"data" already ride along in the JSON
// body itself.
const EVENT_SUBJECTS: Record<WebhookEvent, string> = {
  "host.new": "New host discovered",
  "port.opened": "Port newly open",
  "certificate.expiring_soon": "Certificate expiring soon",
  "saved_search.match": "Saved search matched a new host",
  "vulnerability.high_epss": "High EPSS score on a known CVE",
  "digest.daily": "Daily digest",
};

// Fire-and-forget: dispatch must never slow down or fail the request that
// triggered it (scanner ingest, in particular), so failures are only
// logged, never thrown. Sends both "text" and "content" so the same
// payload renders in Slack and Discord incoming webhooks without needing
// per-target payload shapes; "data" carries the structured fields for
// anything else consuming it directly. Fans out to both channel types
// (see db/types.ts's WebhooksTable) from one query and one events filter -
// they share everything except how the message is actually delivered.
export async function dispatchWebhook(event: WebhookEvent, message: string, data: Record<string, unknown>): Promise<void> {
  let channels: Array<{ id: string; channel_type: string; url: string | null; email_to: string | null; events: string[] }>;
  try {
    channels = await db
      .selectFrom("webhooks")
      .select(["id", "channel_type", "url", "email_to", "events"])
      .where("enabled", "=", true)
      .execute();
  } catch (err) {
    logger.warn({ event: "webhook.lookup_failed", err: err instanceof Error ? err.message : String(err) });
    return;
  }

  const targets = channels.filter((c) => c.events.includes(event));
  const body = JSON.stringify({ text: message, content: message, event, data, timestamp: new Date().toISOString() });
  const subject = `PortTorch: ${EVENT_SUBJECTS[event]}`;

  for (const channel of targets) {
    if (channel.channel_type === "email") {
      if (!channel.email_to) continue;
      sendEmailAlert(channel.email_to, subject, message).catch((err) => {
        logger.warn({
          event: "webhook.delivery_failed",
          webhook_id: channel.id,
          webhook_event: event,
          channel_type: "email",
          error: err instanceof Error ? err.message : String(err),
        });
      });
      continue;
    }

    if (!channel.url) continue;
    fetch(channel.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    })
      .then((res) => {
        if (!res.ok) {
          logger.warn({ event: "webhook.delivery_failed", webhook_id: channel.id, webhook_event: event, status: res.status });
        }
      })
      .catch((err) => {
        logger.warn({
          event: "webhook.delivery_failed",
          webhook_id: channel.id,
          webhook_event: event,
          error: err instanceof Error ? err.message : String(err),
        });
      });
  }
}
