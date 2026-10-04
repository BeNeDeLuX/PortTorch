import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
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

// What changed in one network between two moments, reconstructed from the
// append-only observations the same way current_host_ports defines "now".
describe("GET /api/subnets/changes", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let user: TestUser;
  let restricted: TestUser;
  let client: SessionClient;
  let restrictedClient: SessionClient;
  const ids: Record<string, string> = {};

  async function job(a: TestAgent): Promise<string> {
    const res = await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${a.apiKey}`).send({ targetSpec: "10.97.0.0/24", portSpec: "1-1000" });
    return res.body.id;
  }

  async function host(name: string, ip: string, firstSeenDaysAgo: number, a: TestAgent = agent) {
    const row = await db
      .insertInto("hosts")
      .values({ ip, scanner_agent_id: a.id, first_seen_at: ago(firstSeenDaysAgo), last_seen_at: ago(1) })
      .returning("id")
      .executeTakeFirstOrThrow();
    ids[name] = row.id;
  }

  async function observe(name: string, jobId: string, daysAgo: number, port: number, state: string) {
    await db
      .insertInto("host_port_observations")
      .values({ host_id: ids[name], scan_job_id: jobId, port, protocol: "tcp", state, service_name: "svc", observed_at: ago(daysAgo) })
      .execute();
  }

  beforeAll(async () => {
    agent = await createTestAgent("it-changes");
    other = await createTestAgent("it-changes-other");
    user = await createTestUser("user");
    restricted = await createTestUser("user");
    client = await loginAs(user.username, user.password);
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: other.id }).execute();
    restrictedClient = await loginAs(restricted.username, restricted.password);

    const old = await job(agent);
    const recent = await job(agent);
    const otherJob = await job(other);

    // Known before the window: one port opens and one closes during it.
    await host("changed", "10.97.0.1", 10);
    await observe("changed", old, 10, 22, "open");
    await observe("changed", old, 10, 80, "open");
    await observe("changed", recent, 1, 22, "open");
    await observe("changed", recent, 1, 80, "closed");
    await observe("changed", recent, 1, 443, "open");
    // Known before the window, never reported during it.
    await host("quiet", "10.97.0.2", 10);
    await observe("quiet", old, 10, 22, "open");
    // First found during the window.
    await host("fresh", "10.97.0.3", 2);
    await observe("fresh", recent, 2, 3389, "open");
    // Outside the network asked about.
    await host("elsewhere", "10.98.0.1", 2);
    await observe("elsewhere", recent, 2, 22, "open");
    // Inside the network, but on a scanner the restricted user may not see
    // - and the only one that user may see.
    await host("foreign", "10.97.0.9", 2, other);
    await observe("foreign", otherJob, 2, 21, "open");
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("id", "in", Object.values(ids)).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    await deleteTestUser(user.id);
    await deleteTestUser(restricted.id);
    await closeDb();
  });

  it("reports new hosts, hosts not seen, and ports that opened or closed", async () => {
    const res = await client.get(`/api/subnets/changes?network=10.97.0.0/24&from=${ago(5)}&to=${ago(0)}&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ network: "10.97.0.0/24", hostsBefore: 2, hostsAfter: 3, scansInPeriod: 1 });
    expect(res.body.newHosts.items).toEqual([expect.objectContaining({ ip: "10.97.0.3", openPorts: ["3389/tcp"] })]);
    expect(res.body.unseenHosts.items).toEqual([expect.objectContaining({ ip: "10.97.0.2", openPorts: ["22/tcp"] })]);
    expect(res.body.openedPorts.items.map((p: { ip: string; port: number }) => `${p.ip}:${p.port}`)).toEqual(["10.97.0.1:443"]);
    expect(res.body.closedPorts.items.map((p: { ip: string; port: number }) => `${p.ip}:${p.port}`)).toEqual(["10.97.0.1:80"]);
    expect(res.body.newHosts.truncated).toBe(false);
  });

  it("measures state at each moment, not now", async () => {
    // Ending before the recent scan: nothing it found exists yet.
    const res = await client.get(`/api/subnets/changes?network=10.97.0.0/24&from=${ago(12)}&to=${ago(5)}&scannerAgentId=${agent.id}`);
    expect(res.body.newHosts.items.map((h: { ip: string }) => h.ip).sort()).toEqual(["10.97.0.1", "10.97.0.2"]);
    expect(res.body.newHosts.items.find((h: { ip: string }) => h.ip === "10.97.0.1").openPorts).toEqual(["22/tcp", "80/tcp"]);
    expect(res.body.closedPorts.items).toEqual([]);
  });

  it("reads a partial address as the block it names", async () => {
    const res = await client.get(`/api/subnets/changes?network=10.97.0&from=${ago(5)}&scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    expect(res.body.network).toBe("10.97.0.0/24");
    expect(res.body.newHosts.items).toHaveLength(1);
  });

  it("only shows a restricted session the scanners it may see", async () => {
    const res = await restrictedClient.get(`/api/subnets/changes?network=10.97.0.0/24&from=${ago(5)}`);
    expect(res.body.newHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["10.97.0.9"]);
    expect(res.body.hostsAfter).toBe(1);
  });

  it("refuses what is not a network or not a window", async () => {
    expect((await client.get("/api/subnets/changes?network=web.internal")).status).toBe(400);
    expect((await client.get("/api/subnets/changes")).status).toBe(400);
    expect((await client.get(`/api/subnets/changes?network=10.97.0.0/24&from=${ago(1)}&to=${ago(2)}`)).status).toBe(400);
    expect((await client.get("/api/subnets/changes?network=10.97.0.0/24&from=yesterday")).status).toBe(400);
  });
});
