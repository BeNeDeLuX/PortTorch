import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runOperationalAlertChecks } from "../../src/webhooks/operationalAlerts";
import { closeDb, createTestAgent, deleteTestAgent, type TestAgent } from "./helpers";

// Every webhook event before these was additive - host.new, port.opened,
// nuclei.finding - so nothing ever fired for something that stopped
// existing. These tests drive the real periodic checker (not a
// reimplementation of its query) and assert on both halves that matter:
// that it fires, and that it then stops repeating and resets when the
// condition clears.
describe("presence alerts (scanner.offline, host.disappeared)", () => {
  let agent: TestAgent;
  let webhookId: string;
  const createdHostIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-presence-agent");
    // A real subscribed channel, so the assertions go through the actual
    // dispatch path rather than trusting that the check "would have"
    // fired. The URL is deliberately unroutable - a delivery row is
    // written either way, and what's under test is the routing, not
    // whether some external endpoint answered.
    const row = await db
      .insertInto("webhooks")
      .values({
        name: `it-presence-hook-${Date.now()}`,
        channel_type: "webhook",
        url: "http://127.0.0.1:9/never-listening",
        events: ["scanner.offline", "host.disappeared"],
        enabled: true,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    webhookId = row.id;
  });

  afterEach(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    while (createdHostIds.length) {
      await db.deleteFrom("hosts").where("id", "=", createdHostIds.pop()!).execute();
    }
  });

  afterAll(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function setLastSeen(minutesAgo: number): Promise<void> {
    await db
      .updateTable("scanner_agents")
      .set({ last_seen_at: new Date(Date.now() - minutesAgo * 60_000) })
      .where("id", "=", agent.id)
      .execute();
  }

  async function agentRow() {
    return db
      .selectFrom("scanner_agents")
      .select(["offline_alert_sent_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
  }

  async function deliveredEvents(): Promise<string[]> {
    const rows = await db
      .selectFrom("webhook_deliveries")
      .select(["event"])
      .where("webhook_id", "=", webhookId)
      .execute();
    return rows.map((r) => r.event);
  }

  // dispatchWebhook deliberately does not await the delivery itself ("a
  // slow or dead alert target must never hold up scanner ingest" - see
  // dispatch.ts), so the row lands shortly after the check returns.
  // Polling for it keeps the test honest about that design instead of
  // asserting against a race.
  async function waitForDelivery(event: string, timeoutMs = 3000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if ((await deliveredEvents()).includes(event)) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return false;
  }

  // The negative case can't poll for an absence - it waits out the same
  // window the positive case would have needed, then asserts nothing
  // arrived.
  async function confirmNoDelivery(event: string, settleMs = 750): Promise<boolean> {
    await new Promise((r) => setTimeout(r, settleMs));
    return !(await deliveredEvents()).includes(event);
  }

  async function createHost(ip: string, firstSeenDaysAgo: number, lastSeenDaysAgo: number): Promise<string> {
    const day = 24 * 60 * 60_000;
    const row = await db
      .insertInto("hosts")
      .values({
        ip,
        scanner_agent_id: agent.id,
        hostname: `presence-${ip}`,
        first_seen_at: new Date(Date.now() - firstSeenDaysAgo * day).toISOString(),
        last_seen_at: new Date(Date.now() - lastSeenDaysAgo * day).toISOString(),
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    createdHostIds.push(row.id);
    return row.id;
  }

  it("fires scanner.offline once, not once per check, while the agent stays offline", async () => {
    await setLastSeen(120); // default threshold is 30 minutes
    await runOperationalAlertChecks();

    expect(await waitForDelivery("scanner.offline")).toBe(true);
    expect((await agentRow()).offline_alert_sent_at).not.toBeNull();

    // The condition is unchanged, so a second pass must stay silent -
    // otherwise an offline scanner would alert every five minutes forever.
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await runOperationalAlertChecks();
    expect(await confirmNoDelivery("scanner.offline")).toBe(true);
  });

  it("clears the flag when the agent reports in again, so a later outage alerts again", async () => {
    await setLastSeen(120);
    await runOperationalAlertChecks();
    expect((await agentRow()).offline_alert_sent_at).not.toBeNull();

    await setLastSeen(1); // came back
    await runOperationalAlertChecks();
    expect((await agentRow()).offline_alert_sent_at).toBeNull();

    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await setLastSeen(120); // and went away again
    await runOperationalAlertChecks();
    expect(await waitForDelivery("scanner.offline")).toBe(true);
  });

  it("does not alert for an agent that has never connected at all", async () => {
    // A key created for an install that hasn't finished isn't an outage -
    // same "absence is its own state" reasoning as scanner_agents.version.
    const fresh = await createTestAgent("it-never-connected");
    try {
      await db.updateTable("scanner_agents").set({ last_seen_at: null }).where("id", "=", fresh.id).execute();
      await runOperationalAlertChecks();
      const row = await db
        .selectFrom("scanner_agents")
        .select(["offline_alert_sent_at"])
        .where("id", "=", fresh.id)
        .executeTakeFirstOrThrow();
      expect(row.offline_alert_sent_at).toBeNull();
    } finally {
      await deleteTestAgent(fresh.id);
    }
  });

  it("fires host.disappeared for a long-unseen host and clears it when the host is seen again", async () => {
    await setLastSeen(1); // keep the agent out of the offline path
    const hostId = await createHost("10.77.0.1", 90, 60); // default threshold is 14 days

    await runOperationalAlertChecks();
    expect(await waitForDelivery("host.disappeared")).toBe(true);
    let row = await db.selectFrom("hosts").select(["disappeared_alert_sent_at"]).where("id", "=", hostId).executeTakeFirstOrThrow();
    expect(row.disappeared_alert_sent_at).not.toBeNull();

    await db.updateTable("hosts").set({ last_seen_at: new Date().toISOString() }).where("id", "=", hostId).execute();
    await runOperationalAlertChecks();
    row = await db.selectFrom("hosts").select(["disappeared_alert_sent_at"]).where("id", "=", hostId).executeTakeFirstOrThrow();
    expect(row.disappeared_alert_sent_at).toBeNull();
  });

  it("does not alert for a host first seen only recently", async () => {
    // Discovered yesterday by a one-off ad-hoc scan of a range nothing
    // else covers - not seen since, but it hasn't "disappeared" either.
    await setLastSeen(1);
    const hostId = await createHost("10.77.0.2", 1, 1);
    await runOperationalAlertChecks();
    const row = await db.selectFrom("hosts").select(["disappeared_alert_sent_at"]).where("id", "=", hostId).executeTakeFirstOrThrow();
    expect(row.disappeared_alert_sent_at).toBeNull();
  });
});
