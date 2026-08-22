import { db } from "../db";
import { logger } from "../logger";
import { sendEmailAlert } from "./email";
import { enqueueRetry } from "./retryQueue";

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
  | "scan_queue.backlog"
  | "nuclei.finding";

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
  "nuclei.finding": "Nuclei web vulnerability finding",
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
// The outcome of one delivery attempt. "permanent" exists so a target
// that definitively rejected this exact payload isn't retried forever -
// same permanent/transient split internal/submitqueue already applies to
// host submissions on the scanner side, and for the same reason: an
// unchanged retry of something already refused can only ever fail again.
export type DeliveryOutcome =
  | { ok: true; statusCode: number | null }
  | { ok: false; permanent: boolean; statusCode: number | null; error: string };

export interface DeliveryTarget {
  id: string;
  channel_type: string;
  url: string | null;
  email_to: string | null;
}

// 4xx means the target understood us and refused; retrying byte-identical
// content will not change that. The two exceptions are the ones HTTP
// itself defines as "come back later" - 408 Request Timeout and 429 Too
// Many Requests - which are transient by definition. Everything else (5xx,
// DNS failure, connection refused, TLS error) is transient.
function isPermanentStatus(status: number): boolean {
  if (status === 408 || status === 429) return false;
  return status >= 400 && status < 500;
}

// One delivery attempt against one channel, shared by the initial
// dispatch below and the retry drainer (retryQueue.ts) so a retried alert
// can never be built or sent differently from its first attempt.
export async function attemptDelivery(
  channel: DeliveryTarget,
  event: WebhookEvent,
  message: string,
  data: Record<string, unknown>
): Promise<DeliveryOutcome> {
  if (channel.channel_type === "email") {
    if (!channel.email_to) {
      return { ok: false, permanent: true, statusCode: null, error: "email channel has no recipients" };
    }
    try {
      await sendEmailAlert(channel.email_to, `PortTorch: ${EVENT_SUBJECTS[event]}`, message);
      return { ok: true, statusCode: null };
    } catch (err) {
      const errMessage = err instanceof Error ? err.message : String(err);
      // Unconfigured SMTP is a deployment decision, not a blip: retrying
      // every alert against it would just build a backlog that can only
      // drain after an unrelated config change. The failed delivery row
      // still records it.
      const permanent = errMessage.includes("SMTP is not configured");
      return { ok: false, permanent, statusCode: null, error: errMessage };
    }
  }

  if (!channel.url) {
    return { ok: false, permanent: true, statusCode: null, error: "channel has no url" };
  }

  const body =
    channel.channel_type === "teams"
      ? buildTeamsAdaptiveCardBody(`PortTorch: ${EVENT_SUBJECTS[event]}`, message)
      : JSON.stringify({ text: message, content: message, event, data, timestamp: new Date().toISOString() });

  try {
    const res = await fetch(channel.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    if (res.ok) return { ok: true, statusCode: res.status };
    return {
      ok: false,
      permanent: isPermanentStatus(res.status),
      statusCode: res.status,
      error: `target responded ${res.status}`,
    };
  } catch (err) {
    return { ok: false, permanent: false, statusCode: null, error: err instanceof Error ? err.message : String(err) };
  }
}

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

  for (const channel of channels.filter((c) => c.events.includes(event))) {
    // Still deliberately not awaited: a slow or dead alert target must
    // never hold up scanner ingest, which is what calls this.
    void attemptDelivery(channel, event, message, data).then(async (outcome) => {
      await recordDelivery(channel.id, event, outcome.ok, outcome.statusCode, outcome.ok ? null : outcome.error);
      if (outcome.ok) return;

      logger.warn({
        event: "webhook.delivery_failed",
        webhook_id: channel.id,
        webhook_event: event,
        channel_type: channel.channel_type,
        status: outcome.statusCode,
        error: outcome.error,
        permanent: outcome.permanent,
      });
      if (!outcome.permanent) {
        await enqueueRetry(channel.id, event, message, data, outcome.error);
      }
    });
  }
}
