import http from "http";
import type { AddressInfo } from "net";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { checkResourcePressure, rollupAndPrune } from "../../src/scannerMetrics/metrics";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  getApp,
  loginAs,
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

const MIN = 60_000;
const sample = (at: Date, over: Record<string, number> = {}) => ({
  at: at.toISOString(),
  cpuPercent: 20,
  memUsedBytes: 2 * 1024 ** 3,
  memTotalBytes: 8 * 1024 ** 3,
  netRxBytesPerSec: 1000,
  netTxBytesPerSec: 500,
  load1: 0.5,
  scansRunning: 0,
  ...over,
});

describe("scanner host metrics", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let admin: TestUser;
  let restricted: TestUser;
  let adminClient: SessionClient;
  let restrictedClient: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; data: Record<string, unknown> }> = [];
  let webhookId: string;

  const report = (a: TestAgent, samples: unknown[]) =>
    request(getApp()).post("/api/ingest/metrics").set("Authorization", `Bearer ${a.apiKey}`).send({ samples });

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.writeHead(200).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    webhookId = (
      await db
        .insertInto("webhooks")
        .values({
          name: `it-metrics-${Date.now()}`,
          channel_type: "webhook",
          url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`,
          events: ["scanner.resource_pressure"],
          enabled: true,
        })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;
    agent = await createTestAgent("it-metrics");
    other = await createTestAgent("it-metrics-other");
    admin = await createTestUser("admin");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: other.id }).execute();
    adminClient = await loginAs(admin.username, admin.password);
    restrictedClient = await loginAs(restricted.username, restricted.password);
  });

  afterAll(async () => {
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(restricted.id);
    server.close();
    await closeDb();
  });

  it("stores a batch, ignores a re-sent sample, and drops impossible timestamps", async () => {
    const now = Date.now();
    const batch = [sample(new Date(now - 2 * MIN)), sample(new Date(now - MIN), { cpuPercent: 60, scansRunning: 1 })];
    expect((await report(agent, batch)).status).toBe(204);
    // The same batch again, as after a lost response - plus one from three
    // days ago and one from tomorrow, which no buffer explains.
    expect((await report(agent, [...batch, sample(new Date(now - 3 * 86_400_000)), sample(new Date(now + 86_400_000))])).status).toBe(204);
    const rows = await db.selectFrom("scanner_metrics").select("at").where("scanner_agent_id", "=", agent.id).execute();
    expect(rows).toHaveLength(2);
    expect((await report(agent, [{ ...sample(new Date()), cpuPercent: 250 }])).status).toBe(400);
  });

  it("serves the points, the latest values and the scans that ran", async () => {
    await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${agent.apiKey}`).send({ targetSpec: "10.0.0.0/24", portSpec: "80" });
    const res = await adminClient.get(`/api/agents/${agent.id}/metrics?range=24h`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ range: "24h", source: "minute", agent: { id: agent.id } });
    expect(res.body.points.length).toBeGreaterThanOrEqual(1);
    const p = res.body.points.at(-1);
    expect(typeof p.memUsed).toBe("number");
    expect(p.memTotal).toBe(8 * 1024 ** 3);
    expect(res.body.latest).toMatchObject({ cpuPercent: 60, scansRunning: 1, memTotalBytes: 8 * 1024 ** 3 });
    expect(res.body.scans).toHaveLength(1);
    expect(res.body.scans[0].targetSpec).toBe("10.0.0.0/24");
    // An unknown range falls back rather than running an arbitrary query.
    expect((await adminClient.get(`/api/agents/${agent.id}/metrics?range=forever`)).body.range).toBe("24h");
  });

  it("keeps a restricted session to its own scanners", async () => {
    expect((await restrictedClient.get(`/api/agents/${agent.id}/metrics`)).status).toBe(404);
    expect((await restrictedClient.get(`/api/agents/${other.id}/metrics`)).status).toBe(200);
  });

  it("rolls complete hours up with averages and peaks, and prunes by retention", async () => {
    const hour = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 - 3 * 3_600_000);
    await db
      .insertInto("scanner_metrics")
      .values(
        [10, 20, 90].map((cpu, i) => ({
          scanner_agent_id: other.id,
          at: new Date(hour.getTime() + i * 10 * MIN),
          cpu_percent: cpu,
          mem_used_bytes: 1000 * (i + 1),
          mem_total_bytes: 8000,
          net_rx_bps: 100 * (i + 1),
          net_tx_bps: 10,
          load1: 1,
          scans_running: i,
        }))
      )
      .execute();
    // And one far older than the 14-day raw retention.
    await db
      .insertInto("scanner_metrics")
      .values({ scanner_agent_id: other.id, at: new Date(Date.now() - 20 * 86_400_000), cpu_percent: 5, mem_used_bytes: 1, mem_total_bytes: 8000, net_rx_bps: 0, net_tx_bps: 0, load1: 0, scans_running: 0 })
      .execute();

    await rollupAndPrune();
    const rolled = await db.selectFrom("scanner_metrics_hourly").selectAll().where("scanner_agent_id", "=", other.id).where("hour", "=", hour).executeTakeFirstOrThrow();
    expect(rolled).toMatchObject({ samples: 3, cpu_avg: 40, cpu_max: 90, scans_max: 2, net_rx_max: 300 });
    expect(Number(rolled.mem_used_max)).toBe(3000);
    const old = await db.selectFrom("scanner_metrics").select("at").where("scanner_agent_id", "=", other.id).where("at", "<", new Date(Date.now() - 15 * 86_400_000)).execute();
    expect(old).toHaveLength(0);

    // Running it again changes nothing - it recomputes, it does not add up.
    await rollupAndPrune();
    const again = await db.selectFrom("scanner_metrics_hourly").select("samples").where("scanner_agent_id", "=", other.id).where("hour", "=", hour).executeTakeFirstOrThrow();
    expect(again.samples).toBe(3);

    // Beyond the raw retention, the chart reads the hourly roll-up.
    const long = await adminClient.get(`/api/agents/${other.id}/metrics?range=30d`);
    expect(long.body.source).toBe("hourly");
    expect(long.body.points.some((p: { cpuMax: number }) => p.cpuMax === 90)).toBe(true);
  });

  it("shows hours not yet rolled up in a long-range chart", async () => {
    // Minute samples only, no roll-up has run: the 30-day chart must still
    // end at now rather than an hour (or a restart) earlier.
    const fresh = await createTestAgent("it-metrics-fresh");
    try {
      await report(fresh, [sample(new Date(Date.now() - 2 * MIN), { cpuPercent: 77 })]);
      const res = await adminClient.get(`/api/agents/${fresh.id}/metrics?range=30d`);
      expect(res.body.source).toBe("hourly");
      expect(res.body.points).toHaveLength(1);
      expect(res.body.points[0].cpu).toBe(77);
    } finally {
      await deleteTestAgent(fresh.id);
    }
  });

  it("alerts once on sustained pressure, and again only after it eased", async () => {
    // Only this test's samples in the window - the average is the point.
    await db.deleteFrom("scanner_metrics").where("scanner_agent_id", "=", agent.id).execute();
    const now = new Date();
    const window = (cpu: number, end: Date) =>
      Array.from({ length: 12 }, (_, i) => sample(new Date(end.getTime() - (i + 1) * MIN), { cpuPercent: cpu }));
    await report(agent, window(96, now));

    received = [];
    await checkResourcePressure(now);
    await new Promise((r) => setTimeout(r, 300));
    const mine = received.filter((r) => r.data.scanner_agent_id === agent.id);
    expect(mine).toHaveLength(1);
    expect(mine[0].event).toBe("scanner.resource_pressure");

    received = [];
    await checkResourcePressure(now);
    await new Promise((r) => setTimeout(r, 300));
    expect(received.filter((r) => r.data.scanner_agent_id === agent.id)).toHaveLength(0);

    // A quiet quarter of an hour later the flag is cleared...
    const later = new Date(now.getTime() + 20 * MIN);
    await db.insertInto("scanner_metrics").values(
      Array.from({ length: 12 }, (_, i) => ({
        scanner_agent_id: agent.id,
        at: new Date(later.getTime() - (i + 1) * MIN),
        cpu_percent: 10,
        mem_used_bytes: 1,
        mem_total_bytes: 8000,
        net_rx_bps: 0,
        net_tx_bps: 0,
        load1: 0,
        scans_running: 0,
      }))
    ).execute();
    await checkResourcePressure(later);
    const row = await db.selectFrom("scanner_agents").select("resource_alert_sent_at").where("id", "=", agent.id).executeTakeFirstOrThrow();
    expect(row.resource_alert_sent_at).toBeNull();
  });
});
