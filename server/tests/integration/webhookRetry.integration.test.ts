import http from "http";
import { AddressInfo } from "net";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { dispatchWebhook } from "../../src/webhooks/dispatch";
import { drainWebhookRetryQueue } from "../../src/webhooks/retryQueue";
import { closeDb } from "./helpers";

// A real HTTP target rather than a mocked fetch: the whole point of this
// feature is how it reacts to what a target actually does (status codes,
// a refused connection), and a stub would only ever test the stub. The
// handler is swappable per test so one server covers every case.
let respondWith: (res: http.ServerResponse) => void;
let hits = 0;
let server: http.Server;
let targetUrl: string;

async function startTarget(): Promise<void> {
  server = http.createServer((_req, res) => {
    hits++;
    respondWith(res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  targetUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
}

async function makeWebhook(url: string): Promise<string> {
  const row = await db
    .insertInto("webhooks")
    .values({ name: `it-retry-${Math.random().toString(16).slice(2)}`, channel_type: "webhook", url, events: ["host.new"], enabled: true })
    .returning(["id"])
    .executeTakeFirstOrThrow();
  return row.id;
}

async function queueRows(webhookId: string) {
  return db.selectFrom("webhook_retry_queue").selectAll().where("webhook_id", "=", webhookId).execute();
}

// dispatchWebhook deliberately doesn't await delivery (a dead alert
// target must never hold up scanner ingest), so tests wait for the
// side effect rather than the call.
async function waitForQueue(webhookId: string, expected: number): Promise<Awaited<ReturnType<typeof queueRows>>> {
  for (let i = 0; i < 50; i++) {
    const rows = await queueRows(webhookId);
    if (rows.length === expected) return rows;
    await new Promise((r) => setTimeout(r, 50));
  }
  return queueRows(webhookId);
}

describe("webhook delivery retry", () => {
  const webhookIds: string[] = [];

  beforeEach(() => {
    hits = 0;
  });

  afterAll(async () => {
    for (const id of webhookIds) await db.deleteFrom("webhooks").where("id", "=", id).execute();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await closeDb();
  });

  async function webhook(url?: string): Promise<string> {
    if (!server) await startTarget();
    const id = await makeWebhook(url ?? targetUrl);
    webhookIds.push(id);
    return id;
  }

  it("queues a retry when the target fails transiently", async () => {
    respondWith = (res) => res.writeHead(503).end();
    const id = await webhook();

    await dispatchWebhook("host.new", "first attempt", { a: 1 });
    const rows = await waitForQueue(id, 1);

    expect(rows).toHaveLength(1);
    expect(rows[0].attempt_count).toBe(1);
    expect(rows[0].message).toBe("first attempt");
    expect(rows[0].data).toEqual({ a: 1 });
    expect(rows[0].last_error).toMatch(/503/);
  });

  // A 4xx means the target understood and refused - an unchanged retry
  // can only fail again, so queueing it would just burn attempts.
  it("does not queue a retry for a permanent rejection", async () => {
    respondWith = (res) => res.writeHead(400).end();
    const id = await webhook();

    await dispatchWebhook("host.new", "rejected", {});
    await new Promise((r) => setTimeout(r, 400));

    expect(await queueRows(id)).toHaveLength(0);
    // It still shows up as a failed delivery, so it isn't silently lost.
    const deliveries = await db.selectFrom("webhook_deliveries").selectAll().where("webhook_id", "=", id).execute();
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].success).toBe(false);
  });

  // 429 is the exception to the 4xx rule - HTTP defines it as "come back
  // later", so treating it as permanent would drop alerts against any
  // rate-limiting target.
  it("treats 429 as transient despite being 4xx", async () => {
    respondWith = (res) => res.writeHead(429).end();
    const id = await webhook();

    await dispatchWebhook("host.new", "rate limited", {});
    expect(await waitForQueue(id, 1)).toHaveLength(1);
  });

  it("delivers on a later drain and clears the row", async () => {
    respondWith = (res) => res.writeHead(500).end();
    const id = await webhook();
    await dispatchWebhook("host.new", "will succeed later", {});
    await waitForQueue(id, 1);

    // Make the queued row due now rather than waiting out the backoff.
    await db.updateTable("webhook_retry_queue").set({ next_attempt_at: new Date(Date.now() - 1000) }).where("webhook_id", "=", id).execute();
    respondWith = (res) => res.writeHead(200).end();

    const result = await drainWebhookRetryQueue();
    expect(result.delivered).toBe(1);
    expect(await queueRows(id)).toHaveLength(0);
  });

  it("backs off and eventually gives up rather than retrying forever", async () => {
    respondWith = (res) => res.writeHead(500).end();
    const id = await webhook();
    await dispatchWebhook("host.new", "never succeeds", {});
    await waitForQueue(id, 1);

    const seen: number[] = [];
    for (let i = 0; i < 10; i++) {
      const rows = await queueRows(id);
      if (rows.length === 0) break;
      seen.push(rows[0].attempt_count);
      await db.updateTable("webhook_retry_queue").set({ next_attempt_at: new Date(Date.now() - 1000) }).where("id", "=", rows[0].id).execute();
      await drainWebhookRetryQueue();
    }

    // Attempts strictly increase and the row is gone at the end - the
    // exact cap is BACKOFF_MINUTES.length + 1, asserted as a bound rather
    // than a magic number so tuning the schedule doesn't break this.
    expect(seen).toEqual([...seen].sort((a, b) => a - b));
    expect(seen.length).toBeGreaterThan(1);
    expect(await queueRows(id)).toHaveLength(0);
  });

  // An admin who disables a noisy channel shouldn't then get a burst of
  // everything it missed once the target comes back.
  it("drops a queued retry if the channel was disabled meanwhile", async () => {
    respondWith = (res) => res.writeHead(500).end();
    const id = await webhook();
    await dispatchWebhook("host.new", "channel goes away", {});
    await waitForQueue(id, 1);

    await db.updateTable("webhooks").set({ enabled: false }).where("id", "=", id).execute();
    await db.updateTable("webhook_retry_queue").set({ next_attempt_at: new Date(Date.now() - 1000) }).where("webhook_id", "=", id).execute();

    const hitsBefore = hits;
    const result = await drainWebhookRetryQueue();
    expect(result.gaveUp).toBe(1);
    expect(await queueRows(id)).toHaveLength(0);
    // And it genuinely didn't contact the target again.
    expect(hits).toBe(hitsBefore);
  });

  it("queues a retry when the target is unreachable entirely", async () => {
    // Port 1 on loopback: nothing listens, so this is a connection
    // refusal rather than an HTTP status - the other transient shape.
    const id = await webhook("http://127.0.0.1:1/hook");
    await dispatchWebhook("host.new", "connection refused", {});
    const rows = await waitForQueue(id, 1);
    expect(rows).toHaveLength(1);
    expect(rows[0].last_error).toBeTruthy();
  });
});
