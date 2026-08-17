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

// Class E (240.0.0.0/4) - reserved, never a real target, so it can't
// collide with genuine data when this suite runs against a copy of a
// real database.
const IP = "240.8.9.10";

async function createScanJob(agent: TestAgent): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: IP, portSpec: "22" });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function submitHost(agent: TestAgent, scanJobId: string): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId, hosts: [{ ip: IP, ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] }] });
  expect(res.status).toBe(204);

  const row = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", IP)
    .where("scanner_agent_id", "=", agent.id)
    .executeTakeFirstOrThrow();
  return row.id;
}

describe("DELETE /api/hosts/:id", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-host-delete-agent");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("rejects a non-admin operator with 403", async () => {
    const jobId = await createScanJob(agent);
    const hostId = await submitHost(agent, jobId);

    const res = await operatorClient.delete(`/api/hosts/${hostId}`);
    expect(res.status).toBe(403);

    const stillThere = await db.selectFrom("hosts").select(["id"]).where("id", "=", hostId).executeTakeFirst();
    expect(stillThere).toBeDefined();
  });

  it("returns 404 for an unknown host id", async () => {
    const res = await adminClient.delete("/api/hosts/00000000-0000-0000-0000-000000000000");
    expect(res.status).toBe(404);
  });

  it("returns 400 for a malformed host id", async () => {
    const res = await adminClient.delete("/api/hosts/not-a-uuid");
    expect(res.status).toBe(400);
  });

  it("lets an admin permanently delete a host, cascading tags/comments and clearing scan_requests.host_id", async () => {
    const jobId = await createScanJob(agent);
    const hostId = await submitHost(agent, jobId);

    await adminClient.post(`/api/hosts/${hostId}/tags`).send({ tag: "integration-test-tag" });
    await adminClient.post(`/api/hosts/${hostId}/comments`).send({ body: "integration test comment" });
    const scanRequest = await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: agent.id,
        host_id: hostId,
        target_spec: IP,
        port_spec: "22",
        requested_by: "it-host-delete",
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    const res = await adminClient.delete(`/api/hosts/${hostId}`);
    expect(res.status).toBe(204);

    expect(await db.selectFrom("hosts").select(["id"]).where("id", "=", hostId).executeTakeFirst()).toBeUndefined();
    expect(
      await db.selectFrom("host_tags").select(["id"]).where("host_id", "=", hostId).executeTakeFirst()
    ).toBeUndefined();
    expect(
      await db.selectFrom("host_comments").select(["id"]).where("host_id", "=", hostId).executeTakeFirst()
    ).toBeUndefined();

    const survivingRequest = await db
      .selectFrom("scan_requests")
      .select(["host_id"])
      .where("id", "=", scanRequest.id)
      .executeTakeFirstOrThrow();
    expect(survivingRequest.host_id).toBeNull();

    await db.deleteFrom("scan_requests").where("id", "=", scanRequest.id).execute();
  });
});
