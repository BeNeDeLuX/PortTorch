import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { attemptDelivery, EVENT_SUBJECTS, recordDelivery, type WebhookEvent } from "./dispatch";
import { enqueueRetry } from "./retryQueue";

// Alert bundling for channels with bundle_minutes > 0: per-host events are
// stored here instead of sent, and once the oldest has waited the
// channel's window they go out as one message. Durable, so a restart
// inside the window loses nothing.
//
// The window runs from the first event, not the last - a scan that keeps
// producing events for an hour still reports every few minutes, rather
// than holding everything until it goes quiet.

// Lines listed in the message itself; the rest are counted. The full list
// rides in `data` for a consumer that wants every item.
const MESSAGE_LINES = 40;
const DATA_ITEMS = 500;

export async function collectForBundle(webhookId: string, event: WebhookEvent, message: string, data: Record<string, unknown>): Promise<void> {
  try {
    await db.insertInto("webhook_bundle_items").values({ webhook_id: webhookId, event, message, data: JSON.stringify(data) }).execute();
  } catch (err) {
    logger.warn({ event: "webhook.bundle_store_failed", webhook_id: webhookId, err: err instanceof Error ? err.message : String(err) });
  }
}

export function composeBundle(items: Array<{ event: string; message: string; data: Record<string, unknown> }>, minutes: number) {
  const byEvent: Record<string, number> = {};
  for (const i of items) byEvent[i.event] = (byEvent[i.event] ?? 0) + 1;
  const summary = Object.entries(byEvent)
    .sort((a, b) => b[1] - a[1])
    .map(([e, n]) => `${n} x ${EVENT_SUBJECTS[e as WebhookEvent] ?? e}`)
    .join(", ");
  const lines = items.slice(0, MESSAGE_LINES).map((i) => `- ${i.message}`);
  const more = items.length > MESSAGE_LINES ? [`... and ${items.length - MESSAGE_LINES} more`] : [];
  const message = [`${items.length} alerts in the last ${minutes} minute${minutes === 1 ? "" : "s"}: ${summary}`, "", ...lines, ...more].join("\n");
  return {
    message,
    data: {
      count: items.length,
      by_event: byEvent,
      items: items.slice(0, DATA_ITEMS).map((i) => ({ event: i.event, message: i.message, data: i.data })),
      truncated: items.length > DATA_ITEMS,
    },
  };
}

// Sends every bundle whose window is up. Items are claimed by deleting
// them in the same statement that reads them, so two overlapping runs
// cannot send one item twice. A single item goes out as the event it was,
// not as a bundle of one.
export async function flushBundles(now = new Date()): Promise<number> {
  const due = await sql<{ webhook_id: string; bundle_minutes: number }>`
    SELECT b.webhook_id, w.bundle_minutes
    FROM webhook_bundle_items b JOIN webhooks w ON w.id = b.webhook_id
    GROUP BY b.webhook_id, w.bundle_minutes
    HAVING min(b.created_at) <= ${now.toISOString()}::timestamptz - make_interval(mins => w.bundle_minutes)
  `.execute(db);
  let sent = 0;
  for (const d of due.rows) {
    const claimed = await sql<{ event: string; message: string; data: Record<string, unknown>; created_at: Date }>`
      DELETE FROM webhook_bundle_items WHERE webhook_id = ${d.webhook_id}
      RETURNING event, message, data, created_at
    `.execute(db);
    const items = claimed.rows.sort((a, b) => a.created_at.getTime() - b.created_at.getTime());
    if (items.length === 0) continue;
    const channel = await db
      .selectFrom("webhooks")
      .select(["id", "channel_type", "url", "email_to", "verify_tls", "enabled"])
      .where("id", "=", d.webhook_id)
      .executeTakeFirst();
    // Disabled since the items were collected: dropped, the same as the
    // retry queue drops a disabled channel's backlog.
    if (!channel?.enabled) continue;
    const single = items.length === 1;
    const event = (single ? items[0].event : "alerts.bundle") as WebhookEvent;
    const { message, data } = single ? { message: items[0].message, data: items[0].data } : composeBundle(items, d.bundle_minutes);
    const outcome = await attemptDelivery(channel, event, message, data);
    await recordDelivery(channel.id, event, outcome.ok, outcome.statusCode, outcome.ok ? null : outcome.error);
    if (!outcome.ok && !outcome.permanent) await enqueueRetry(channel.id, event, message, data, outcome.error);
    sent++;
  }
  return sent;
}

export function startBundleFlusher(): void {
  setInterval(() => {
    flushBundles().catch((err) => logger.error({ event: "webhook.bundle_flush_failed", err: err instanceof Error ? err.message : String(err) }));
  }, 30_000);
}
