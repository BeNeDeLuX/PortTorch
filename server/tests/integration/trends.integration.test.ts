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

// Class E (240.0.0.0/4) - reserved, never a real target, so these can't
// collide with genuine data even run against a copy of a real database.
const IP_A = "240.6.1.1";
const IP_B = "240.6.1.2";
const PORT = 22;

async function ingestOpenPort(agent: TestAgent, ip: string): Promise<void> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: String(PORT) });
  await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId: jobRes.body.id, hosts: [{ ip, ports: [{ port: PORT, protocol: "tcp", state: "open" }] }] });
}

function todayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

describe("GET /api/trends", () => {
  let admin: TestUser;
  let restrictedOperator: TestUser;
  let adminClient: SessionClient;
  let restrictedClient: SessionClient;
  let agentA: TestAgent;
  let agentB: TestAgent;

  beforeAll(async () => {
    agentA = await createTestAgent("it-trends-agent-a");
    agentB = await createTestAgent("it-trends-agent-b");

    admin = await createTestUser("admin");
    restrictedOperator = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restrictedOperator.id, scanner_agent_id: agentA.id }).execute();

    adminClient = await loginAs(admin.username, admin.password);
    restrictedClient = await loginAs(restrictedOperator.username, restrictedOperator.password);

    await ingestOpenPort(agentA, IP_A);
    await ingestOpenPort(agentB, IP_B);
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "in", [IP_A, IP_B]).execute();
    await deleteTestUser(admin.id);
    await deleteTestUser(restrictedOperator.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  it("counts today's new hosts, scans, and open ports from both scanners for an unrestricted admin", async () => {
    const res = await adminClient.get("/api/trends").query({ days: 7 });
    expect(res.status).toBe(200);
    expect(res.body.series).toHaveLength(7);

    const today = res.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(today).toBeDefined();
    // >= rather than === - other tests/fixtures in the shared test
    // database may contribute to the same day's fleet-wide counts.
    expect(today.newHosts).toBeGreaterThanOrEqual(2);
    expect(today.scans).toBeGreaterThanOrEqual(2);
    expect(today.openPorts).toBeGreaterThanOrEqual(2);
    expect(today.totalHosts).toBeGreaterThanOrEqual(today.newHosts);
  });

  it("defaults to 90 days and clamps an out-of-range days value", async () => {
    const defaultRes = await adminClient.get("/api/trends");
    expect(defaultRes.body.days).toBe(90);
    expect(defaultRes.body.series).toHaveLength(90);

    const clampedRes = await adminClient.get("/api/trends").query({ days: 99999 });
    expect(clampedRes.body.days).toBe(365);
    expect(clampedRes.body.series).toHaveLength(365);
  });

  it("scopes counts to only the restricted operator's allowed scanner agent", async () => {
    const res = await restrictedClient.get("/api/trends").query({ days: 7 });
    expect(res.status).toBe(200);

    const today = res.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(today).toBeDefined();
    // Exactly 1 - restricted to agentA only, so agentB's host/scan/port
    // must not be counted (unlike the admin test above, which can't use
    // an exact count since it also sees whatever else is in the shared
    // database - this restricted view is scoped down to just agentA).
    expect(today.newHosts).toBe(1);
    expect(today.scans).toBe(1);
    expect(today.openPorts).toBe(1);
  });

  it("requires authentication", async () => {
    const res = await request(getApp()).get("/api/trends");
    expect(res.status).toBe(401);
  });

  it("the scannerAgentId filter scopes an unrestricted admin down to just the picked scanner(s)", async () => {
    const onlyA = await adminClient.get("/api/trends").query({ days: 7, scannerAgentId: agentA.id });
    const todayA = onlyA.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(todayA.newHosts).toBe(1);
    expect(todayA.scans).toBe(1);
    expect(todayA.openPorts).toBe(1);

    const both = await adminClient.get("/api/trends").query({ days: 7, scannerAgentId: `${agentA.id},${agentB.id}` });
    const todayBoth = both.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(todayBoth.newHosts).toBeGreaterThanOrEqual(2);
  });

  it("the scannerAgentId filter can only narrow a restricted session, never widen it past agentA", async () => {
    // restrictedOperator is scoped to agentA only - explicitly asking for
    // agentB too must not leak its data in (the session restriction and
    // the picked filter are AND'd, not OR'd).
    const res = await restrictedClient.get("/api/trends").query({ days: 7, scannerAgentId: `${agentA.id},${agentB.id}` });
    const today = res.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(today.newHosts).toBe(1);
    expect(today.scans).toBe(1);
    expect(today.openPorts).toBe(1);
  });
});
