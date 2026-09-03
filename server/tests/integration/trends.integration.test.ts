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
// Fake, never-real CPEs so the cve_cache rows this test seeds can't collide
// with anything a real NVD sync would ever cache.
const CPE_A = "cpe:/a:porttorch-test:trend-a:1.0";
const CPE_B = "cpe:/a:porttorch-test:trend-b:1.0";

async function ingestOpenPort(agent: TestAgent, ip: string, cpe: string): Promise<void> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: String(PORT) });
  await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId: jobRes.body.id, hosts: [{ ip, ports: [{ port: PORT, protocol: "tcp", state: "open", cpes: [cpe] }] }] });
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

    await ingestOpenPort(agentA, IP_A, CPE_A);
    await ingestOpenPort(agentB, IP_B, CPE_B);

    // Seed cve_cache directly rather than waiting on the real (rate-limited,
    // external) NVD sync - trends/routes.ts only ever reads this table, it
    // doesn't care how a row got there.
    await db
      .insertInto("cve_cache")
      .values([
        { cpe: CPE_A, cves: JSON.stringify([{ id: "CVE-1999-0001", description: "test", cvssScore: 9.8, cvssSeverity: "CRITICAL", published: null }]) },
        { cpe: CPE_B, cves: JSON.stringify([{ id: "CVE-1999-0002", description: "test", cvssScore: 5.0, cvssSeverity: "MEDIUM", published: null }]) },
      ])
      .execute();

    // One of the two is in CISA's KEV catalog, which is what separates
    // the two new severity-weighted series from the plain cveMatches one.
    await db
      .insertInto("kev_cache")
      .values({
        cve_id: "CVE-1999-0001",
        vendor_project: "porttorch-test",
        product: "trend-a",
        vulnerability_name: "test",
        date_added: "2024-01-01",
      })
      .onConflict((oc) => oc.column("cve_id").doNothing())
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "in", [IP_A, IP_B]).execute();
    await db.deleteFrom("cve_cache").where("cpe", "in", [CPE_A, CPE_B]).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "=", "CVE-1999-0001").execute();
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
    expect(today.hostsScanned).toBeGreaterThanOrEqual(2);
    expect(today.openPorts).toBeGreaterThanOrEqual(2);
    expect(today.cveMatches).toBeGreaterThanOrEqual(2);
    expect(today.totalHosts).toBeGreaterThanOrEqual(today.newHosts);
  });

  it("separates high-severity and known-exploited matches from the plain CVE count", async () => {
    const res = await adminClient.get("/api/trends").query({ days: 7, scannerAgentId: agentA.id });
    const today = res.body.series.find((d: { date: string }) => d.date === todayKey());

    // Scoped to agent A, whose only CVE is the CVSS 9.8 KEV-listed one -
    // so all three series see it, which is what makes the assertions
    // below exact rather than >= like the fleet-wide test above.
    expect(today.cveMatches).toBe(1);
    expect(today.highCveMatches).toBe(1);
    expect(today.kevMatches).toBe(1);

    // Agent B's CVE is a 5.0 that is not KEV-listed, so it counts once
    // and only once - the case that would break if the severity filter
    // were dropped or the KEV join were made a left join by accident.
    const resB = await adminClient.get("/api/trends").query({ days: 7, scannerAgentId: agentB.id });
    const todayB = resB.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(todayB.cveMatches).toBe(1);
    expect(todayB.highCveMatches).toBe(0);
    expect(todayB.kevMatches).toBe(0);
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
    expect(today.hostsScanned).toBe(1);
    expect(today.openPorts).toBe(1);
    expect(today.cveMatches).toBe(1);
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
    expect(todayA.hostsScanned).toBe(1);
    expect(todayA.openPorts).toBe(1);
    expect(todayA.cveMatches).toBe(1);

    const both = await adminClient.get("/api/trends").query({ days: 7, scannerAgentId: `${agentA.id},${agentB.id}` });
    const todayBoth = both.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(todayBoth.newHosts).toBeGreaterThanOrEqual(2);
    expect(todayBoth.hostsScanned).toBeGreaterThanOrEqual(2);
  });

  it("the scannerAgentId filter can only narrow a restricted session, never widen it past agentA", async () => {
    // restrictedOperator is scoped to agentA only - explicitly asking for
    // agentB too must not leak its data in (the session restriction and
    // the picked filter are AND'd, not OR'd).
    const res = await restrictedClient.get("/api/trends").query({ days: 7, scannerAgentId: `${agentA.id},${agentB.id}` });
    const today = res.body.series.find((d: { date: string }) => d.date === todayKey());
    expect(today.newHosts).toBe(1);
    expect(today.scans).toBe(1);
    expect(today.hostsScanned).toBe(1);
    expect(today.openPorts).toBe(1);
    expect(today.cveMatches).toBe(1);
  });
});
