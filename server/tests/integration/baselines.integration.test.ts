import http from "http";
import { sql } from "kysely";
import type { AddressInfo } from "net";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkBaselines } from "../../src/baselines/deviations";
import { db } from "../../src/db";
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

const DAY = 24 * 60 * 60 * 1000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

// A baseline is "this network looked right at this moment". What changed
// since is the Changes view's comparison, and the alert fires once per
// deviation rather than on every check.
describe("network baselines", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let operator: TestUser;
  let viewer: TestUser;
  let restricted: TestUser;
  let op: SessionClient;
  let view: SessionClient;
  let restrictedClient: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; data: Record<string, unknown> }> = [];
  let webhookId: string;
  const hostIds: string[] = [];

  async function job(a: TestAgent): Promise<string> {
    const res = await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${a.apiKey}`).send({ targetSpec: "10.96.0.0/24", portSpec: "1-1000" });
    return res.body.id;
  }

  async function host(ip: string, firstSeenDaysAgo: number, a: TestAgent = agent): Promise<string> {
    const row = await db
      .insertInto("hosts")
      .values({ ip, scanner_agent_id: a.id, first_seen_at: ago(firstSeenDaysAgo), last_seen_at: ago(0) })
      .returning("id")
      .executeTakeFirstOrThrow();
    hostIds.push(row.id);
    return row.id;
  }

  async function observe(hostId: string, jobId: string, daysAgo: number, port: number, state = "open") {
    await db
      .insertInto("host_port_observations")
      .values({ host_id: hostId, scan_job_id: jobId, port, protocol: "tcp", state, service_name: "svc", observed_at: ago(daysAgo) })
      .execute();
  }

  async function waitForDeliveries(count: number) {
    for (let i = 0; i < 50 && received.length < count; i++) await new Promise((r) => setTimeout(r, 50));
  }

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
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
    webhookId = (
      await db
        .insertInto("webhooks")
        .values({ name: `it-baseline-${Date.now()}`, channel_type: "webhook", url, events: ["baseline.deviation"], enabled: true })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;

    agent = await createTestAgent("it-baseline");
    other = await createTestAgent("it-baseline-other");
    operator = await createTestUser("operator");
    viewer = await createTestUser("user");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: other.id }).execute();
    op = await loginAs(operator.username, operator.password);
    view = await loginAs(viewer.username, viewer.password);
    restrictedClient = await loginAs(restricted.username, restricted.password);

    const old = await job(agent);
    const a = await host("10.96.0.1", 10);
    await observe(a, old, 10, 22);
    await observe(a, old, 10, 80);
  });

  afterAll(async () => {
    await db.deleteFrom("network_baselines").where(sql<boolean>`network <<= '10.96.0.0/16'::cidr`).execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("hosts").where("id", "in", hostIds).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    for (const u of [operator, viewer, restricted]) await deleteTestUser(u.id);
    server.close();
    await closeDb();
  });

  let baselineId: string;

  it("approves a network's current state, and only an operator may", async () => {
    expect((await view.post("/api/baselines").send({ network: "10.96.0" })).status).toBe(403);
    const res = await op.post("/api/baselines").send({ network: "10.96.0", note: "server segment" });
    expect(res.status).toBe(201);
    expect(res.body.network).toBe("10.96.0.0/24");
    baselineId = res.body.id;
    // The same network typed differently is the same baseline.
    expect((await op.post("/api/baselines").send({ network: "10.96.0.77/24" })).status).toBe(409);
    expect((await op.post("/api/baselines").send({ network: "web.internal" })).status).toBe(400);

    const list = await view.get("/api/baselines");
    const mine = list.body.find((b: { id: string }) => b.id === baselineId);
    expect(mine).toMatchObject({ network: "10.96.0.0/24", note: "server segment", approved_by: operator.username });
    expect(mine.deviations).toMatchObject({ newHosts: 0, openedPorts: 0, closedPorts: 0, alerting: 0 });
  });

  it("reports what changed since, and alerts on each deviation once", async () => {
    // Backdate the approval so the "recent" scan lands after it.
    await db.updateTable("network_baselines").set({ approved_at: ago(5) }).where("id", "=", baselineId).execute();
    const recent = await job(agent);
    const [a] = hostIds;
    await observe(a, recent, 1, 22);
    await observe(a, recent, 1, 80, "closed");
    await observe(a, recent, 1, 3389);
    const fresh = await host("10.96.0.5", 2);
    await observe(fresh, recent, 2, 443);

    const detail = await view.get(`/api/baselines/${baselineId}`);
    expect(detail.body.changes.newHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["10.96.0.5"]);
    expect(detail.body.changes.openedPorts.items.map((p: { port: number }) => p.port)).toEqual([3389]);
    expect(detail.body.changes.closedPorts.items.map((p: { port: number }) => p.port)).toEqual([80]);

    received = [];
    expect(await checkBaselines()).toBeGreaterThanOrEqual(1);
    await waitForDeliveries(1);
    const mine = received.filter((r) => r.data.baseline_id === baselineId);
    expect(mine).toHaveLength(1);
    expect(mine[0].event).toBe("baseline.deviation");
    expect(mine[0].data).toMatchObject({
      network: "10.96.0.0/24",
      new_hosts: [{ ip: "10.96.0.5", open_ports: ["443/tcp"] }],
      opened_ports: [expect.objectContaining({ ip: "10.96.0.1", port: 3389 })],
      closed_ports: [expect.objectContaining({ ip: "10.96.0.1", port: 80 })],
    });

    // Nothing new: the next check stays quiet.
    received = [];
    await checkBaselines();
    await new Promise((r) => setTimeout(r, 300));
    expect(received.filter((r) => r.data.baseline_id === baselineId)).toHaveLength(0);

    // One more port: only that one is reported.
    const later = await job(agent);
    await observe(a, later, 0.5, 8443);
    received = [];
    await checkBaselines();
    await waitForDeliveries(1);
    const next = received.filter((r) => r.data.baseline_id === baselineId);
    expect(next).toHaveLength(1);
    expect(next[0].data.new_hosts).toEqual([]);
    expect((next[0].data.opened_ports as Array<{ port: number }>).map((p) => p.port)).toEqual([8443]);
  });

  it("accepts every deviation by approving again", async () => {
    expect((await view.post(`/api/baselines/${baselineId}/approve`).send({})).status).toBe(403);
    expect((await op.post(`/api/baselines/${baselineId}/approve`).send({})).status).toBe(204);
    const list = await view.get("/api/baselines");
    expect(list.body.find((b: { id: string }) => b.id === baselineId).deviations.alerting).toBe(0);
    const row = await db.selectFrom("network_baselines").select("alerted_keys").where("id", "=", baselineId).executeTakeFirstOrThrow();
    expect(row.alerted_keys).toEqual([]);
  });

  it("keeps a restricted session to its own scanners", async () => {
    // Cannot create a baseline over every scanner, or over someone else's.
    expect((await restrictedClient.post("/api/baselines").send({ network: "10.96.1.0/24" })).status).toBe(403);
    expect((await restrictedClient.post("/api/baselines").send({ network: "10.96.1.0/24", scannerAgentId: agent.id })).status).toBe(403);
    const own = await restrictedClient.post("/api/baselines").send({ network: "10.96.1.0/24", scannerAgentId: other.id });
    expect(own.status).toBe(201);

    // A baseline scoped to a scanner it cannot see is invisible to it.
    const scoped = await op.post("/api/baselines").send({ network: "10.96.2.0/24", scannerAgentId: agent.id });
    const visible = (await restrictedClient.get("/api/baselines")).body.map((b: { id: string }) => b.id);
    expect(visible).toContain(own.body.id);
    expect(visible).not.toContain(scoped.body.id);
    expect((await restrictedClient.get(`/api/baselines/${scoped.body.id}`)).status).toBe(404);
    expect((await restrictedClient.delete(`/api/baselines/${scoped.body.id}`)).status).toBe(404);

    // The global baseline is visible, its deviations narrowed to what the
    // session may see - none of agent's hosts.
    const global = await restrictedClient.get(`/api/baselines/${baselineId}`);
    expect(global.status).toBe(200);
    expect(global.body.changes.newHosts.items).toEqual([]);
  });

  it("deletes", async () => {
    expect((await op.delete(`/api/baselines/${baselineId}`)).status).toBe(204);
    expect((await view.get(`/api/baselines/${baselineId}`)).status).toBe(404);
  });
});
