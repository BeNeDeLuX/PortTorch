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

// The rate only matters if it survives all the way to what the scanner
// actually claims - a value stored but not returned by
// GET /api/ingest/scan-requests/next would be silently useless.
describe("per-scan masscan rate", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let client: SessionClient;
  const createdIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-rate-agent");
    operator = await createTestUser("operator");
    client = await loginAs(operator.username, operator.password);
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await deleteTestUser(operator.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("stores an explicit rate and hands it to the scanner on claim", async () => {
    const freshAgent = await createTestAgent("it-rate-claim-agent");
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: freshAgent.id,
      targetSpec: "240.11.1.1",
      portSpec: "80",
      masscanRate: 250,
    });
    expect(res.status).toBe(201);
    createdIds.push(res.body.id);

    const row = await db
      .selectFrom("scan_requests")
      .select(["masscan_rate"])
      .where("id", "=", res.body.id)
      .executeTakeFirstOrThrow();
    expect(row.masscan_rate).toBe(250);

    const claim = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${freshAgent.apiKey}`);
    expect(claim.status).toBe(200);
    expect(claim.body.masscanRate).toBe(250);

    await deleteTestAgent(freshAgent.id);
  });

  it("defaults to null - omitting it must keep the scanner's own configured rate", async () => {
    const freshAgent = await createTestAgent("it-rate-default-agent");
    const res = await client
      .post("/api/adhoc-scans")
      .send({ scannerAgentId: freshAgent.id, targetSpec: "240.11.1.2", portSpec: "80" });
    expect(res.status).toBe(201);
    createdIds.push(res.body.id);

    const row = await db
      .selectFrom("scan_requests")
      .select(["masscan_rate"])
      .where("id", "=", res.body.id)
      .executeTakeFirstOrThrow();
    expect(row.masscan_rate).toBeNull();

    const claim = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${freshAgent.apiKey}`);
    expect(claim.body.masscanRate).toBeNull();

    await deleteTestAgent(freshAgent.id);
  });

  it("rejects a non-positive rate rather than letting it reach masscan", async () => {
    for (const bad of [0, -100]) {
      const res = await client
        .post("/api/adhoc-scans")
        .send({ scannerAgentId: agent.id, targetSpec: "240.11.1.3", portSpec: "80", masscanRate: bad });
      expect(res.status).toBe(400);
    }
  });

  it("is snapshotted from a schedule onto each request it spawns", async () => {
    const admin = await createTestUser("admin");
    const adminClient = await loginAs(admin.username, admin.password);

    const created = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agent.id,
      targetSpec: "240.11.1.4",
      portSpec: "443",
      intervalMinutes: 60,
      masscanRate: 500,
    });
    expect(created.status).toBe(201);

    const scheduleRow = await db
      .selectFrom("scan_schedules")
      .select(["masscan_rate"])
      .where("id", "=", created.body.id)
      .executeTakeFirstOrThrow();
    expect(scheduleRow.masscan_rate).toBe(500);

    await db.deleteFrom("scan_schedules").where("id", "=", created.body.id).execute();
    await deleteTestUser(admin.id);
  });

  it("is settable through the External API too", async () => {
    const { createTestApiToken, deleteTestApiToken } = await import("./helpers");
    const token = await createTestApiToken("it-rate-token");
    const freshAgent = await createTestAgent("it-rate-extapi-agent");

    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: freshAgent.name, targetSpec: "240.11.1.5", portSpec: "80", masscanRate: 42 });
    expect(res.status).toBe(201);
    createdIds.push(res.body.scanRequestId);

    const row = await db
      .selectFrom("scan_requests")
      .select(["masscan_rate"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(row.masscan_rate).toBe(42);

    await deleteTestAgent(freshAgent.id);
    await deleteTestApiToken(token.id);
  });
});
