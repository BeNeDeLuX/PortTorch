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
const IP_A = "240.4.1.1";
const IP_B = "240.4.1.2";
const PORT_A = 18080;
const PORT_B = 19090;

async function ingestHostWithCert(
  agent: TestAgent,
  ip: string,
  port: number,
  cpe: string
): Promise<{ hostId: string; scanJobId: string }> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: String(port) });
  const scanJobId = jobRes.body.id;

  await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId, hosts: [{ ip, ports: [{ port, protocol: "tcp", state: "open", cpes: [cpe] }] }] });

  await request(getApp())
    .post("/api/ingest/tls-certificates")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({
      scanJobId,
      hostIp: ip,
      port,
      subjectCn: `${ip}-cert`,
      fingerprintSha256: `fingerprint-${ip}-${port}`,
    });

  const hostRow = await db.selectFrom("hosts").select(["id"]).where("ip", "=", ip).executeTakeFirstOrThrow();
  return { hostId: hostRow.id, scanJobId };
}

// Covers the confirmed scope: an admin can restrict an operator/user
// account to specific scanner agents, and that restriction must apply to
// the *entire* fleet-wide picture - not just the main host list - plus
// close the IDOR gap where a restricted account could otherwise still
// view/mutate an out-of-scope resource directly by id.
describe("per-user scanner-agent visibility restriction", () => {
  let admin: TestUser;
  let unrestrictedOperator: TestUser;
  let restrictedOperator: TestUser;
  let adminClient: SessionClient;
  let unrestrictedClient: SessionClient;
  let restrictedClient: SessionClient;
  let agentA: TestAgent;
  let agentB: TestAgent;
  let hostAId: string;
  let hostBId: string;
  let scanJobHistoryA: string;
  let scanJobHistoryB: string;
  let scanJobActiveA: string;
  let scanJobActiveB: string;
  let scanRequestA: string;
  let scanRequestB: string;
  let scheduleA: string;
  let scheduleB: string;
  const cpeA = "cpe:/a:it-restrict:host-a";
  const cpeB = "cpe:/a:it-restrict:host-b";
  const createdUserIds: number[] = [];

  beforeAll(async () => {
    agentA = await createTestAgent("it-restrict-agent-a");
    agentB = await createTestAgent("it-restrict-agent-b");

    admin = await createTestUser("admin");
    unrestrictedOperator = await createTestUser("operator");
    restrictedOperator = await createTestUser("operator");
    // Assigned directly, simulating what POST /api/users or PATCH
    // /:id/scanner-agents would have done - the assignment API itself is
    // covered separately below. Must happen before login, since the
    // restriction is loaded into the session at login time.
    await db.insertInto("user_scanner_agents").values({ user_id: restrictedOperator.id, scanner_agent_id: agentA.id }).execute();

    adminClient = await loginAs(admin.username, admin.password);
    unrestrictedClient = await loginAs(unrestrictedOperator.username, unrestrictedOperator.password);
    restrictedClient = await loginAs(restrictedOperator.username, restrictedOperator.password);

    const a = await ingestHostWithCert(agentA, IP_A, PORT_A, cpeA);
    const b = await ingestHostWithCert(agentB, IP_B, PORT_B, cpeB);
    hostAId = a.hostId;
    hostBId = b.hostId;

    await db
      .insertInto("cve_cache")
      .values([
        { cpe: cpeA, cves: JSON.stringify([{ id: "CVE-2020-0001", description: "host A cve", cvssScore: 9.8, cvssSeverity: "CRITICAL", published: null }]) },
        { cpe: cpeB, cves: JSON.stringify([{ id: "CVE-2020-0002", description: "host B cve", cvssScore: 9.8, cvssSeverity: "CRITICAL", published: null }]) },
      ])
      .execute();

    const historyA = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agentA.id, target_spec: IP_A, port_spec: String(PORT_A), status: "completed", finished_at: new Date() })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanJobHistoryA = historyA.id;
    const historyB = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agentB.id, target_spec: IP_B, port_spec: String(PORT_B), status: "completed", finished_at: new Date() })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanJobHistoryB = historyB.id;

    const activeA = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agentA.id, target_spec: IP_A, port_spec: String(PORT_A), status: "running" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanJobActiveA = activeA.id;
    const activeB = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agentB.id, target_spec: IP_B, port_spec: String(PORT_B), status: "running" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanJobActiveB = activeB.id;

    const reqA = await db
      .insertInto("scan_requests")
      .values({ scanner_agent_id: agentA.id, target_spec: IP_A, port_spec: String(PORT_A), status: "pending", requested_by: "integration-test" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanRequestA = reqA.id;
    const reqB = await db
      .insertInto("scan_requests")
      .values({ scanner_agent_id: agentB.id, target_spec: IP_B, port_spec: String(PORT_B), status: "pending", requested_by: "integration-test" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scanRequestB = reqB.id;

    const schedARes = await adminClient
      .post("/api/schedules")
      .send({ scheduleType: "interval", scannerAgentId: agentA.id, targetSpec: IP_A, portSpec: String(PORT_A), intervalMinutes: 60 });
    scheduleA = schedARes.body.id;
    const schedBRes = await adminClient
      .post("/api/schedules")
      .send({ scheduleType: "interval", scannerAgentId: agentB.id, targetSpec: IP_B, portSpec: String(PORT_B), intervalMinutes: 60 });
    scheduleB = schedBRes.body.id;
  });

  afterAll(async () => {
    await db.deleteFrom("scan_schedules").where("id", "in", [scheduleA, scheduleB]).execute();
    await db.deleteFrom("hosts").where("ip", "in", [IP_A, IP_B]).execute();
    await db.deleteFrom("scan_jobs").where("id", "in", [scanJobHistoryA, scanJobHistoryB, scanJobActiveA, scanJobActiveB]).execute();
    await db.deleteFrom("scan_requests").where("id", "in", [scanRequestA, scanRequestB]).execute();
    await db.deleteFrom("cve_cache").where("cpe", "in", [cpeA, cpeB]).execute();
    for (const id of createdUserIds) {
      await deleteTestUser(id);
    }
    await deleteTestUser(admin.id);
    await deleteTestUser(unrestrictedOperator.id);
    await deleteTestUser(restrictedOperator.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  it("unrestricted operator (no assignment rows) still sees both scanners' hosts and agents - the backward-compat default", async () => {
    const hosts = await unrestrictedClient.get("/api/hosts").query({ pageSize: 200 });
    const ips = (hosts.body.items as Array<{ ip: string }>).map((h) => h.ip);
    expect(ips).toContain(IP_A);
    expect(ips).toContain(IP_B);

    const agents = await unrestrictedClient.get("/api/agents");
    const agentIds = (agents.body as Array<{ id: string }>).map((a) => a.id);
    expect(agentIds).toContain(agentA.id);
    expect(agentIds).toContain(agentB.id);
  });

  it("restricted operator only sees agentA's host in the list, facets (even with no other filter), and CSV export", async () => {
    const hosts = await restrictedClient.get("/api/hosts").query({ pageSize: 200 });
    const ips = (hosts.body.items as Array<{ ip: string }>).map((h) => h.ip);
    expect(ips).toContain(IP_A);
    expect(ips).not.toContain(IP_B);

    // No query filters at all - regression test for the hasActiveHostFilters
    // fast-path that must still apply the restriction.
    const facets = await restrictedClient.get("/api/hosts/facets");
    const ports = (facets.body.ports as Array<{ port: number }>).map((p) => p.port);
    expect(ports).toContain(PORT_A);
    expect(ports).not.toContain(PORT_B);

    const csv = await restrictedClient.get("/api/hosts/export.csv");
    expect(csv.text).toContain(IP_A);
    expect(csv.text).not.toContain(IP_B);
  });

  it("restricted operator gets 404 for an out-of-scope host, both for viewing and for every mutating route", async () => {
    const getRes = await restrictedClient.get(`/api/hosts/${hostBId}`);
    expect(getRes.status).toBe(404);

    const getOwn = await restrictedClient.get(`/api/hosts/${hostAId}`);
    expect(getOwn.status).toBe(200);

    const tagRes = await restrictedClient.post(`/api/hosts/${hostBId}/tags`).send({ tag: "test" });
    expect(tagRes.status).toBe(404);

    const probeRes = await restrictedClient.patch(`/api/hosts/${hostBId}/probe-hostname`).send({ hostname: "example.com" });
    expect(probeRes.status).toBe(404);

    const rescanRes = await restrictedClient.post(`/api/hosts/${hostBId}/rescan`);
    expect(rescanRes.status).toBe(404);

    const commentRes = await restrictedClient.post(`/api/hosts/${hostBId}/comments`).send({ body: "test" });
    expect(commentRes.status).toBe(404);
  });

  it("restricted operator only sees agentA's scan jobs/requests, and gets 404 acting on agentB's by id", async () => {
    const active = await restrictedClient.get("/api/scan-jobs/active");
    const activeIds = (active.body as Array<{ id: string }>).map((j) => j.id);
    expect(activeIds).toContain(scanJobActiveA);
    expect(activeIds).not.toContain(scanJobActiveB);

    const history = await restrictedClient.get("/api/scan-jobs/history").query({ status: "completed" });
    const historyIds = (history.body.items as Array<{ id: string }>).map((j) => j.id);
    expect(historyIds).toContain(scanJobHistoryA);
    expect(historyIds).not.toContain(scanJobHistoryB);

    const queue = await restrictedClient.get("/api/scan-jobs/queue");
    const queueIds = (queue.body as Array<{ id: string }>).map((r) => r.id);
    expect(queueIds).toContain(scanRequestA);
    expect(queueIds).not.toContain(scanRequestB);

    const cancelQueueB = await restrictedClient.post(`/api/scan-jobs/queue/${scanRequestB}/cancel`);
    expect(cancelQueueB.status).toBe(404);

    const dismissB = await restrictedClient.post(`/api/scan-jobs/${scanJobActiveB}/dismiss`);
    expect(dismissB.status).toBe(404);

    const cancelJobB = await restrictedClient.post(`/api/scan-jobs/${scanJobActiveB}/cancel`);
    expect(cancelJobB.status).toBe(404);
  });

  it("restricted operator only sees agentA's data in digest, vulnerabilities, certificates, agents, and schedules", async () => {
    const digest = await restrictedClient.get("/api/digest");
    const digestIps = [...digest.body.newHosts, ...digest.body.changedHosts].map((h: { ip: string }) => h.ip);
    expect(digestIps).toContain(IP_A);
    expect(digestIps).not.toContain(IP_B);

    const vulns = await restrictedClient.get("/api/vulnerabilities");
    const vulnHostIds = (vulns.body as Array<{ host_id: string }>).map((v) => v.host_id);
    expect(vulnHostIds).toContain(hostAId);
    expect(vulnHostIds).not.toContain(hostBId);

    const certs = await restrictedClient.get("/api/certificates");
    const certHostIds = (certs.body as Array<{ host_id: string }>).map((c) => c.host_id);
    expect(certHostIds).toContain(hostAId);
    expect(certHostIds).not.toContain(hostBId);

    const agents = await restrictedClient.get("/api/agents");
    const agentIds = (agents.body as Array<{ id: string }>).map((a) => a.id);
    expect(agentIds).toContain(agentA.id);
    expect(agentIds).not.toContain(agentB.id);

    const schedules = await restrictedClient.get("/api/schedules");
    const scheduleIds = (schedules.body as Array<{ id: string }>).map((s) => s.id);
    expect(scheduleIds).toContain(scheduleA);
    expect(scheduleIds).not.toContain(scheduleB);
  });

  it("admin always sees both scanners' data regardless of any restriction", async () => {
    const hosts = await adminClient.get("/api/hosts").query({ pageSize: 200 });
    const ips = (hosts.body.items as Array<{ ip: string }>).map((h) => h.ip);
    expect(ips).toContain(IP_A);
    expect(ips).toContain(IP_B);

    const schedules = await adminClient.get("/api/schedules");
    const scheduleIds = (schedules.body as Array<{ id: string }>).map((s) => s.id);
    expect(scheduleIds).toContain(scheduleA);
    expect(scheduleIds).toContain(scheduleB);
  });

  it("admin can create a user restricted to one scanner agent, and the users list reflects it", async () => {
    const res = await adminClient
      .post("/api/users")
      .send({ username: `it-scoped-${Date.now()}`, password: "Test-Password1", role: "operator", scannerAgentIds: [agentA.id] });
    expect(res.status).toBe(201);
    expect(res.body.scannerAgentIds).toEqual([agentA.id]);
    createdUserIds.push(res.body.id);

    const list = await adminClient.get("/api/users");
    const found = (list.body as Array<{ id: number; scannerAgentIds: string[] }>).find((u) => u.id === res.body.id);
    expect(found?.scannerAgentIds).toEqual([agentA.id]);
  });

  it("ignores scannerAgentIds sent alongside an admin-role creation", async () => {
    const res = await adminClient
      .post("/api/users")
      .send({ username: `it-admin-${Date.now()}`, password: "Test-Password1", role: "admin", scannerAgentIds: [agentA.id] });
    expect(res.status).toBe(201);
    expect(res.body.scannerAgentIds).toEqual([]);
    createdUserIds.push(res.body.id);

    const rows = await db.selectFrom("user_scanner_agents").select(["user_id"]).where("user_id", "=", res.body.id).execute();
    expect(rows).toHaveLength(0);
  });

  it("rejects an unknown scanner agent id on creation", async () => {
    const res = await adminClient
      .post("/api/users")
      .send({ username: `it-badagent-${Date.now()}`, password: "Test-Password1", role: "user", scannerAgentIds: ["00000000-0000-0000-0000-000000000000"] });
    expect(res.status).toBe(400);
  });

  it("PATCH /:id/scanner-agents updates, clears (empty array), and rejects an admin target", async () => {
    const created = await adminClient
      .post("/api/users")
      .send({ username: `it-patchtarget-${Date.now()}`, password: "Test-Password1", role: "user" });
    createdUserIds.push(created.body.id);

    const setRes = await adminClient.patch(`/api/users/${created.body.id}/scanner-agents`).send({ scannerAgentIds: [agentA.id, agentB.id] });
    expect(setRes.status).toBe(200);
    expect(setRes.body.scannerAgentIds.sort()).toEqual([agentA.id, agentB.id].sort());

    const clearRes = await adminClient.patch(`/api/users/${created.body.id}/scanner-agents`).send({ scannerAgentIds: [] });
    expect(clearRes.status).toBe(200);
    expect(clearRes.body.scannerAgentIds).toEqual([]);

    const adminTargetRes = await adminClient.patch(`/api/users/${admin.id}/scanner-agents`).send({ scannerAgentIds: [agentA.id] });
    expect(adminTargetRes.status).toBe(400);
  });

  it("rejects a non-admin from managing users or scanner assignments", async () => {
    const res = await restrictedClient.post("/api/users").send({ username: "should-fail", password: "Test-Password1", role: "user" });
    expect(res.status).toBe(403);

    const patchRes = await restrictedClient.patch(`/api/users/${unrestrictedOperator.id}/scanner-agents`).send({ scannerAgentIds: [] });
    expect(patchRes.status).toBe(403);
  });
});
