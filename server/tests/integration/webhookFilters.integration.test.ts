import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { sql } from "kysely";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  getApp,
  loginAs,
  type TestAgent,
  type TestUser,
} from "./helpers";

const HOST_PROD = "240.90.0.1";
const HOST_LAB = "240.90.0.2";

// A channel that cannot be narrowed is a channel somebody eventually
// mutes, and a muted channel is worse than none - it still looks
// configured. These drive the real ingest path, not the filter function
// in isolation.
describe("webhook channel filters", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let admin: TestUser;
  const hookIds: string[] = [];

  async function makeHook(name: string, filters: Record<string, unknown>): Promise<string> {
    const row = await db
      .insertInto("webhooks")
      .values({
        name: `${name}-${Date.now()}-${Math.random()}`,
        channel_type: "webhook",
        url: "http://127.0.0.1:9/never-listening",
        events: ["host.new", "nuclei.finding", "scanner.offline"],
        enabled: true,
        ...filters,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    hookIds.push(row.id);
    return row.id;
  }

  beforeAll(async () => {
    agentA = await createTestAgent("it-filter-a");
    agentB = await createTestAgent("it-filter-b");
    admin = await createTestUser("admin");
  });

  afterAll(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "in", hookIds).execute();
    await db.deleteFrom("webhooks").where("id", "in", hookIds).execute();
    await sql`DELETE FROM hosts WHERE ip = ${HOST_PROD}::inet OR ip = ${HOST_LAB}::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agentA.id, agentB.id]).execute();
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  afterEach(async () => {
    await db.deleteFrom("webhook_deliveries").where("webhook_id", "in", hookIds).execute();
    await sql`DELETE FROM hosts WHERE ip = ${HOST_PROD}::inet OR ip = ${HOST_LAB}::inet`.execute(db);
  });

  async function submitHost(agent: TestAgent, ip: string, tags: string[]): Promise<void> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: ip, portSpec: "22" });
    expect(job.status).toBe(201);

    const res = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: job.body.id, hosts: [{ ip, ports: [{ port: 22, protocol: "tcp", state: "open" }] }] });
    expect(res.status).toBe(204);

    if (tags.length) {
      const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", ip).executeTakeFirstOrThrow();
      await db.insertInto("host_tags").values(tags.map((tag) => ({ host_id: host.id, tag }))).execute();
    }
  }

  async function deliveriesFor(hookId: string, timeoutMs = 2000): Promise<string[]> {
    // dispatchWebhook deliberately doesn't await delivery, so the rows
    // land shortly after the request returns.
    const deadline = Date.now() + timeoutMs;
    let rows: Array<{ event: string }> = [];
    while (Date.now() < deadline) {
      rows = await db.selectFrom("webhook_deliveries").select(["event"]).where("webhook_id", "=", hookId).execute();
      if (rows.length > 0) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    return rows.map((r) => r.event);
  }

  it("delivers to an unfiltered channel exactly as before", async () => {
    const hook = await makeHook("it-nofilter", {});
    await submitHost(agentA, HOST_PROD, []);
    expect(await deliveriesFor(hook)).toContain("host.new");
  });

  it("narrows by scanner", async () => {
    const onlyB = await makeHook("it-scanner", { filter_scanner_agent_ids: [agentB.id] });
    await submitHost(agentA, HOST_PROD, []);
    // Nothing from scanner A.
    await new Promise((r) => setTimeout(r, 800));
    expect(await deliveriesFor(onlyB, 100)).toHaveLength(0);

    await submitHost(agentB, HOST_LAB, []);
    expect(await deliveriesFor(onlyB)).toContain("host.new");
  });

  it("narrows by host tag, including tags applied by the same scan", async () => {
    // Auto-tags are written inside the ingest transaction, so the filter
    // has to read tags after it commits - otherwise "only alert for
    // WebServer" would never fire on the scan that found the web server.
    const onlyProd = await makeHook("it-tag", { filter_tags: ["prod"] });
    await submitHost(agentA, HOST_LAB, ["lab"]);
    await new Promise((r) => setTimeout(r, 800));
    expect(await deliveriesFor(onlyProd, 100)).toHaveLength(0);
  });

  it("never suppresses a fleet-level alert with a host filter set", async () => {
    // scanner.offline is about a scanner, not a host: a tag filter must
    // not swallow it, or narrowing the noisy alerts would silently cost
    // the infrastructure ones.
    const onlyProd = await makeHook("it-fleet", { filter_tags: ["prod"] });
    const { runOperationalAlertChecks } = await import("../../src/webhooks/operationalAlerts");
    await db
      .updateTable("scanner_agents")
      .set({ last_seen_at: new Date(Date.now() - 24 * 60 * 60_000), offline_alert_sent_at: null })
      .where("id", "=", agentA.id)
      .execute();
    await runOperationalAlertChecks();
    expect(await deliveriesFor(onlyProd)).toContain("scanner.offline");
  });

  it("rejects an event name it does not know, and accepts every one it offers", async () => {
    // The create schema's event list had already drifted from the one the
    // API serves to the picker - subscribing to the two newest events
    // failed with a 400 that named no cause.
    const client = await loginAs(admin.username, admin.password);
    const offered = await client.get("/api/webhooks/events");
    expect(offered.status).toBe(200);

    const created = await client.post("/api/webhooks").send({
      name: `it-allevents-${Date.now()}`,
      channelType: "webhook",
      url: "http://127.0.0.1:9/never-listening",
      events: offered.body,
    });
    expect(created.status).toBe(201);
    hookIds.push(created.body.id);

    const bad = await client.post("/api/webhooks").send({
      name: "it-bad",
      channelType: "webhook",
      url: "http://127.0.0.1:9/x",
      events: ["not.an.event"],
    });
    expect(bad.status).toBe(400);
  });
});
