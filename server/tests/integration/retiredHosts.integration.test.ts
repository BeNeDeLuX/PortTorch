import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runOperationalAlertChecks } from "../../src/webhooks/operationalAlerts";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  loginAs,
  type TestAgent,
  type TestUser,
} from "./helpers";

const RETIRED_IP = "240.40.0.1";
const LIVE_IP = "240.40.0.2";

// host.disappeared says "decommissioned, or down" and had no way to answer
// the first case: a deliberately switched-off server alerted forever, and
// the only way to stop it was deleting the host and losing its history.
describe("retiring a host", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let webhookId: string;
  let retiredId: string;
  let liveId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-retired-agent");
    operator = await createTestUser("operator");

    const row = await db
      .insertInto("webhooks")
      .values({
        name: `it-retired-hook-${Date.now()}`,
        channel_type: "webhook",
        url: "http://127.0.0.1:9/never-listening",
        events: ["host.disappeared"],
        enabled: true,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    webhookId = row.id;

    // Both hosts are long past any plausible disappeared threshold.
    const longAgo = new Date(Date.now() - 400 * 24 * 60 * 60_000).toISOString();
    for (const ip of [RETIRED_IP, LIVE_IP]) {
      const host = await db
        .insertInto("hosts")
        .values({ ip, scanner_agent_id: agent.id, first_seen_at: longAgo, last_seen_at: longAgo })
        .returning(["id"])
        .executeTakeFirstOrThrow();
      if (ip === RETIRED_IP) retiredId = host.id;
      else liveId = host.id;
    }
  });

  afterAll(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "=", webhookId).execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    for (const ip of [RETIRED_IP, LIVE_IP]) {
      await db.deleteFrom("hosts").where("ip", "=", ip).execute();
    }
    await deleteTestAgent(agent.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("suppresses host.disappeared for a retired host but not for its neighbour", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.patch(`/api/hosts/${retiredId}/retired`).send({ retired: true });
    expect(res.status).toBe(200);
    expect(res.body.retired_at).not.toBeNull();

    await runOperationalAlertChecks();

    const retired = await db
      .selectFrom("hosts")
      .select(["disappeared_alert_sent_at"])
      .where("id", "=", retiredId)
      .executeTakeFirstOrThrow();
    const live = await db
      .selectFrom("hosts")
      .select(["disappeared_alert_sent_at"])
      .where("id", "=", liveId)
      .executeTakeFirstOrThrow();

    // The neighbour proves the check ran at all - without it, a silent
    // retired host would be indistinguishable from a check that never
    // looked.
    expect(live.disappeared_alert_sent_at).not.toBeNull();
    expect(retired.disappeared_alert_sent_at).toBeNull();
  });

  it("keeps the host and its history rather than deleting it", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.get(`/api/hosts/${retiredId}`);
    expect(res.status).toBe(200);
    expect(res.body.host.retired_at).not.toBeNull();
  });

  it("is filtered out only when hideRetired is asked for", async () => {
    const client = await loginAs(operator.username, operator.password);

    const shown = await client.get(`/api/hosts?q=${RETIRED_IP}`);
    expect(shown.status).toBe(200);
    expect(shown.body.items.map((h: { id: string }) => h.id)).toContain(retiredId);

    const hidden = await client.get(`/api/hosts?q=${RETIRED_IP}&hideRetired=true`);
    expect(hidden.body.items.map((h: { id: string }) => h.id)).not.toContain(retiredId);
  });

  it("alerts again once un-retired", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.patch(`/api/hosts/${retiredId}/retired`).send({ retired: false });
    expect(res.status).toBe(200);
    expect(res.body.retired_at).toBeNull();

    await runOperationalAlertChecks();
    const row = await db
      .selectFrom("hosts")
      .select(["disappeared_alert_sent_at"])
      .where("id", "=", retiredId)
      .executeTakeFirstOrThrow();
    expect(row.disappeared_alert_sent_at).not.toBeNull();
  });
});
