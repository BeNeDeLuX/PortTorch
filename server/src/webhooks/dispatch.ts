import { db } from "../db";
import { logger } from "../logger";
import { sendEmailAlert } from "./email";

// Most recent deliveries kept per webhook (webhook_deliveries table) -
// a diagnostic tail for the Webhooks page's "History" view, not a
// permanent record, so it's trimmed at insert time rather than left to
// grow forever like audit_log.
const MAX_DELIVERIES_PER_WEBHOOK = 50;

// Best-effort, like recordAudit - a failed write here must never affect
// delivery itself, which has already happened (or failed) by the time
// this is called. Exported so webhooks/routes.ts's "/test" endpoint can
// record its own send too ("test" isn't a real WebhookEvent - it's the
// same synthetic value that endpoint's own test payload already uses) -
// without this, the one action an admin is most likely to check the
// History modal right after (clicking "Test") would show nothing.
export async function recordDelivery(
  webhookId: string,
  event: WebhookEvent | "test",
  success: boolean,
  statusCode: number | null,
  error: string | null
): Promise<void> {
  try {
    await db
      .insertInto("webhook_deliveries")
      .values({ webhook_id: webhookId, event, success, status_code: statusCode, error })
      .execute();
    await db
      .deleteFrom("webhook_deliveries")
      .where("webhook_id", "=", webhookId)
      .where(
        "id",
        "not in",
        db
          .selectFrom("webhook_deliveries")
          .select("id")
          .where("webhook_id", "=", webhookId)
          .orderBy("created_at", "desc")
          .limit(MAX_DELIVERIES_PER_WEBHOOK)
      )
      .execute();
  } catch (err) {
    logger.warn({ event: "webhook.delivery_record_failed", webhook_id: webhookId, err: err instanceof Error ? err.message : String(err) });
  }
}

export type WebhookEvent =
  | "host.new"
  | "port.opened"
  | "certificate.expiring_soon"
  | "webserver_certificate.expiring_soon"
  | "saved_search.match"
  | "vulnerability.high_epss"
  | "vulnerability.kev"
  | "digest.daily"
  | "scan.stale"
  | "scanner.update_failed"
  | "scan_queue.backlog";

// Plain-English subject line for an email channel - a webhook channel has
// no equivalent need, since "event"/"data" already ride along in the JSON
// body itself.
const EVENT_SUBJECTS: Record<WebhookEvent, string> = {
  "host.new": "New host discovered",
  "port.opened": "Port newly open",
  "certificate.expiring_soon": "Certificate expiring soon",
  "webserver_certificate.expiring_soon": "Webserver TLS certificate expiring soon",
  "saved_search.match": "Saved search matched a new host",
  "vulnerability.high_epss": "High EPSS score on a known CVE",
  "vulnerability.kev": "CVE added to CISA's Known Exploited Vulnerabilities catalog",
  "digest.daily": "Daily digest",
  "scan.stale": "Scan looks stalled",
  "scanner.update_failed": "Scanner self-update failed",
  "scan_queue.backlog": "Scan queue backlog",
};

// A Teams "Workflows" webhook (the current replacement for the classic,
// now-deprecated "Incoming Webhook" connector - the classic connector
// happened to also accept the same plain {text: ...} shape the generic
// "webhook" channel already sends, but that path is being retired) expects
// its POST body wrapped as a bot-framework "message" activity carrying an
// Adaptive Card attachment, not a bare {text} object - confirmed against
// Microsoft's own Adaptive Card + Workflows documentation, not guessed.
// Exported so webhooks/routes.ts's "/test" endpoint sends the exact same
// shape a real event would, rather than a second, hand-rolled test body.
export function buildTeamsAdaptiveCardBody(title: string, message: string): string {
  return JSON.stringify({
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body: [
            { type: "TextBlock", text: title, weight: "bolder", size: "medium", wrap: true },
            { type: "TextBlock", text: message, wrap: true },
          ],
        },
      },
    ],
  });
}

// Fire-and-forget: dispatch must never slow down or fail the request that
// triggered it (scanner ingest, in particular), so failures are only
// logged, never thrown. Sends both "text" and "content" so the same
// payload renders in Slack and Discord incoming webhooks without needing
// per-target payload shapes; "data" carries the structured fields for
// anything else consuming it directly. Fans out to all three channel types
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
  const slackDiscordBody = JSON.stringify({ text: message, content: message, event, data, timestamp: new Date().toISOString() });
  const teamsBody = buildTeamsAdaptiveCardBody(`PortTorch: ${EVENT_SUBJECTS[event]}`, message);
  const subject = `PortTorch: ${EVENT_SUBJECTS[event]}`;

  for (const channel of targets) {
    if (channel.channel_type === "email") {
      if (!channel.email_to) continue;
      sendEmailAlert(channel.email_to, subject, message)
        .then(() => recordDelivery(channel.id, event, true, null, null))
        .catch((err) => {
          const errMessage = err instanceof Error ? err.message : String(err);
          logger.warn({
            event: "webhook.delivery_failed",
            webhook_id: channel.id,
            webhook_event: event,
            channel_type: "email",
            error: errMessage,
          });
          recordDelivery(channel.id, event, false, null, errMessage);
        });
      continue;
    }

    if (!channel.url) continue;
    fetch(channel.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: channel.channel_type === "teams" ? teamsBody : slackDiscordBody,
    })
      .then((res) => {
        if (!res.ok) {
          logger.warn({ event: "webhook.delivery_failed", webhook_id: channel.id, webhook_event: event, status: res.status });
        }
        recordDelivery(channel.id, event, res.ok, res.status, null);
      })
      .catch((err) => {
        const errMessage = err instanceof Error ? err.message : String(err);
        logger.warn({
          event: "webhook.delivery_failed",
          webhook_id: channel.id,
          webhook_event: event,
          error: errMessage,
        });
        recordDelivery(channel.id, event, false, null, errMessage);
      });
  }
}
