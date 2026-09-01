import { db } from "../db";
import { logger } from "../logger";
import { WebhookEvent, attemptDelivery, recordDelivery } from "./dispatch";

// Backoff schedule, indexed by how many attempts have already failed.
// The first retry is quick because the overwhelming majority of real
// failures are a target being restarted or a momentary network blip;
// later ones back off so a target that's down for hours isn't hammered.
// After the last entry the alert is given up on - alerts are
// time-sensitive, and one delivered a day late is worse than useless
// because it reads as a current event.
const BACKOFF_MINUTES = [1, 5, 15, 60];
const MAX_ATTEMPTS = BACKOFF_MINUTES.length + 1;

// Same 60s cadence as scheduler.ts - fine-grained enough for a 1-minute
// first retry without polling an empty table pointlessly often.
const DRAIN_INTERVAL_MS = 60_000;

function nextAttemptAt(attemptCount: number): Date {
  const minutes = BACKOFF_MINUTES[Math.min(attemptCount - 1, BACKOFF_MINUTES.length - 1)];
  return new Date(Date.now() + minutes * 60_000);
}

// Called from dispatchWebhook for a transient failure only - a permanent
// one is recorded and dropped rather than queued (see attemptDelivery's
// DeliveryOutcome). Best-effort like recordAudit/recordDelivery: a failed
// enqueue must never propagate into whatever triggered the alert, which
// on the hot path is scanner ingest.
export async function enqueueRetry(
  webhookId: string,
  event: WebhookEvent,
  message: string,
  data: Record<string, unknown>,
  lastError: string
): Promise<void> {
  try {
    await db
      .insertInto("webhook_retry_queue")
      .values({
        webhook_id: webhookId,
        event,
        message,
        data: JSON.stringify(data),
        attempt_count: 1,
        next_attempt_at: nextAttemptAt(1),
        last_error: lastError,
      })
      .execute();
  } catch (err) {
    logger.warn({ event: "webhook.retry_enqueue_failed", webhook_id: webhookId, err: err instanceof Error ? err.message : String(err) });
  }
}

// Exported for the same reason retention.ts's runRetentionSweep is: the
// scheduled job's own logic, callable directly, so a test exercises
// exactly what the ticker runs rather than a parallel reimplementation.
export async function drainWebhookRetryQueue(): Promise<{ delivered: number; retrying: number; gaveUp: number }> {
  const due = await db
    .selectFrom("webhook_retry_queue")
    .selectAll()
    .where("next_attempt_at", "<=", new Date())
    .orderBy("next_attempt_at", "asc")
    // Bounded per tick so one large backlog can't monopolise the loop.
    .limit(50)
    .execute();

  let delivered = 0;
  let retrying = 0;
  let gaveUp = 0;

  for (const row of due) {
    // Re-read the channel each time rather than snapshotting it onto the
    // queue row: an admin who fixed a wrong URL, or disabled the channel
    // entirely, should have that take effect on the next retry. A
    // disabled or deleted channel drops the pending alert - the admin
    // said they don't want it.
    const channel = await db
      .selectFrom("webhooks")
      .select(["id", "channel_type", "url", "email_to", "enabled", "verify_tls"])
      .where("id", "=", row.webhook_id)
      .executeTakeFirst();
    if (!channel || !channel.enabled) {
      await db.deleteFrom("webhook_retry_queue").where("id", "=", row.id).execute();
      gaveUp++;
      continue;
    }

    const outcome = await attemptDelivery(channel, row.event as WebhookEvent, row.message, row.data ?? {});
    await recordDelivery(channel.id, row.event as WebhookEvent, outcome.ok, outcome.statusCode, outcome.ok ? null : outcome.error);

    if (outcome.ok) {
      await db.deleteFrom("webhook_retry_queue").where("id", "=", row.id).execute();
      delivered++;
      logger.info({
        event: "webhook.retry_succeeded",
        webhook_id: channel.id,
        webhook_event: row.event,
        attempts: row.attempt_count + 1,
      });
      continue;
    }

    const attempts = row.attempt_count + 1;
    if (outcome.permanent || attempts >= MAX_ATTEMPTS) {
      await db.deleteFrom("webhook_retry_queue").where("id", "=", row.id).execute();
      gaveUp++;
      logger.warn({
        event: "webhook.retry_gave_up",
        webhook_id: channel.id,
        webhook_event: row.event,
        attempts,
        permanent: outcome.permanent,
        error: outcome.error,
      });
      continue;
    }

    await db
      .updateTable("webhook_retry_queue")
      .set({ attempt_count: attempts, next_attempt_at: nextAttemptAt(attempts), last_error: outcome.error })
      .where("id", "=", row.id)
      .execute();
    retrying++;
  }

  return { delivered, retrying, gaveUp };
}

export function startWebhookRetryQueue(): void {
  setInterval(() => {
    drainWebhookRetryQueue().catch((err) =>
      logger.error({ event: "webhook.retry_drain_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, DRAIN_INTERVAL_MS);
}
