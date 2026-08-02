import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
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

// Class E (240.0.0.0/4) - reserved, never a real target, so it can't
// collide with genuine data even run against a copy of a real database.
// Two different IPs (not one shared one) since host identity is (ip,
// scanner_agent_id) - reusing one ip for both agents would just upsert
// into a single host, not two distinguishable ones.
const IP_A = "240.3.1.1";
const IP_B = "240.3.1.2";

async function ingestHost(agent: TestAgent, ip: string): Promise<string> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: "443" });
  await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId: jobRes.body.id, hosts: [{ ip, ports: [{ port: 443, protocol: "tcp", state: "open" }] }] });

  const hostRow = await db.selectFrom("hosts").select(["id"]).where("ip", "=", ip).executeTakeFirstOrThrow();
  return hostRow.id;
}

// Covers the reported bug's fix: a manual per-host "probe hostname"
// override the scanner uses instead of the bare IP for TLS SNI / the
// gowitness screenshot URL, needed when a target only routes correctly
// (e.g. nginx-style SNI-based virtual hosting) for a known hostname.
describe("host probe-hostname override", () => {
  let admin: TestUser;
  let operator: TestUser;
  let readOnlyUser: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;
  let readOnlyClient: SessionClient;
  let agentA: TestAgent;
  let agentB: TestAgent;
  let hostAId: string;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    readOnlyUser = await createTestUser("user");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
    readOnlyClient = await loginAs(readOnlyUser.username, readOnlyUser.password);
    agentA = await createTestAgent("it-probehost-agent-a");
    agentB = await createTestAgent("it-probehost-agent-b");
    hostAId = await ingestHost(agentA, IP_A);
    await ingestHost(agentB, IP_B);
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "in", [IP_A, IP_B]).execute();
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await deleteTestUser(readOnlyUser.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  afterEach(async () => {
    await db.updateTable("hosts").set({ probe_hostname: null }).where("ip", "in", [IP_A, IP_B]).execute();
  });

  it("lets an operator set a probe hostname on a host", async () => {
    const res = await operatorClient.patch(`/api/hosts/${hostAId}/probe-hostname`).send({ hostname: "example.com" });
    expect(res.status).toBe(200);
    expect(res.body.probe_hostname).toBe("example.com");

    const host = await adminClient.get(`/api/hosts/${hostAId}`);
    expect(host.body.host.probe_hostname).toBe("example.com");
  });

  it("lets an explicit null clear it back to no override", async () => {
    await operatorClient.patch(`/api/hosts/${hostAId}/probe-hostname`).send({ hostname: "example.com" });
    const res = await operatorClient.patch(`/api/hosts/${hostAId}/probe-hostname`).send({ hostname: null });
    expect(res.status).toBe(200);
    expect(res.body.probe_hostname).toBeNull();
  });

  it("rejects a read-only user", async () => {
    const res = await readOnlyClient.patch(`/api/hosts/${hostAId}/probe-hostname`).send({ hostname: "example.com" });
    expect(res.status).toBe(403);
  });

  it("returns 404 for an unknown host id", async () => {
    const res = await operatorClient
      .patch("/api/hosts/00000000-0000-0000-0000-000000000000/probe-hostname")
      .send({ hostname: "example.com" });
    expect(res.status).toBe(404);
  });

  it("GET /api/ingest/probe-hostnames only returns the requesting scanner's own hosts with an override set", async () => {
    await operatorClient.patch(`/api/hosts/${hostAId}/probe-hostname`).send({ hostname: "example.com" });

    const asA = await request(getApp())
      .get("/api/ingest/probe-hostnames")
      .set("Authorization", `Bearer ${agentA.apiKey}`);
    expect(asA.status).toBe(200);
    expect(asA.body).toEqual([{ ip: IP_A, hostname: "example.com" }]);

    // agentB's own host (IP_B) has no override set, and it must never see
    // agentA's override even though both were ingested in this same suite -
    // a host's identity is (ip, scanner_agent_id), so this must not leak.
    const asB = await request(getApp())
      .get("/api/ingest/probe-hostnames")
      .set("Authorization", `Bearer ${agentB.apiKey}`);
    expect(asB.status).toBe(200);
    expect(asB.body).toEqual([]);
  });
});
