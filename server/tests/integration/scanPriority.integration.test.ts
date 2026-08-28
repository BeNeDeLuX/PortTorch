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
  type TestAgent,
  type TestUser,
} from "./helpers";

// The whole point of scan_requests.priority is that a request queued
// *later* can be claimed *earlier* - so the test that matters inserts in
// deliberately the wrong order and drains the queue through the scanner's
// real claim endpoint, rather than asserting on an ORDER BY in isolation.
describe("scan queue priority", () => {
  let agent: TestAgent;
  let operator: TestUser;

  beforeAll(async () => {
    agent = await createTestAgent("it-priority-agent");
    operator = await createTestUser("operator");
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  const insertedRequestIds: string[] = [];

  afterEach(async () => {
    while (insertedRequestIds.length) {
      await db.deleteFrom("scan_requests").where("id", "=", insertedRequestIds.pop()!).execute();
    }
  });

  async function insertPending(targetSpec: string, priority: "high" | "normal" | "low"): Promise<string> {
    const row = await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: agent.id,
        target_spec: targetSpec,
        port_spec: "1-1000",
        status: "pending",
        requested_by: "integration-test",
        priority,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    insertedRequestIds.push(row.id);
    return row.id;
  }

  async function claim(): Promise<{ status: number; targetSpec?: string }> {
    const res = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${agent.apiKey}`);
    return { status: res.status, targetSpec: res.body?.targetSpec };
  }

  it("claims high before normal before low, regardless of insert order", async () => {
    // Inserted low-first so plain created_at FIFO - the pre-priority
    // behavior - would drain them in exactly the opposite order.
    await insertPending("10.9.0.1", "low");
    await insertPending("10.9.0.2", "normal");
    await insertPending("10.9.0.3", "high");

    expect((await claim()).targetSpec).toBe("10.9.0.3");
    expect((await claim()).targetSpec).toBe("10.9.0.2");
    expect((await claim()).targetSpec).toBe("10.9.0.1");
    expect((await claim()).status).toBe(204);
  });

  it("stays first-in-first-out within one priority level", async () => {
    await insertPending("10.9.1.1", "normal");
    await insertPending("10.9.1.2", "normal");
    await insertPending("10.9.1.3", "normal");

    expect((await claim()).targetSpec).toBe("10.9.1.1");
    expect((await claim()).targetSpec).toBe("10.9.1.2");
    expect((await claim()).targetSpec).toBe("10.9.1.3");
  });

  it("defaults an untouched request to normal, so pre-existing rows keep FIFO order", async () => {
    const row = await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "10.9.2.1",
        port_spec: "80",
        status: "pending",
        requested_by: "integration-test",
      })
      .returning(["id", "priority"])
      .executeTakeFirstOrThrow();
    insertedRequestIds.push(row.id);
    expect(row.priority).toBe("normal");
  });

  it("rejects a priority value outside the three allowed ones", async () => {
    await expect(
      db
        .insertInto("scan_requests")
        .values({
          scanner_agent_id: agent.id,
          target_spec: "10.9.3.1",
          port_spec: "80",
          status: "pending",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          priority: "urgent" as any,
        })
        .execute()
    ).rejects.toThrow();
  });

  it("orders the dashboard's queue view the same way the scanner claims", async () => {
    await insertPending("10.9.4.1", "low");
    await insertPending("10.9.4.2", "high");
    const client = await loginAs(operator.username, operator.password);

    const res = await client.get("/api/scan-jobs/queue");
    expect(res.status).toBe(200);
    const mine = (res.body as { target_spec: string; priority: string }[]).filter((r) =>
      r.target_spec.startsWith("10.9.4.")
    );
    expect(mine.map((r) => r.target_spec)).toEqual(["10.9.4.2", "10.9.4.1"]);
    expect(mine.map((r) => r.priority)).toEqual(["high", "low"]);
  });

  it("lets an operator queue an ad-hoc scan at high priority", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "10.9.5.1",
      portSpec: "443",
      priority: "high",
    });
    expect(res.status).toBe(201);
    expect(res.body.priority).toBe("high");
    insertedRequestIds.push(res.body.id);
  });

  it("defaults an ad-hoc scan with no priority field to normal", async () => {
    // The External API's own ad-hoc endpoint never sends one, so this is
    // what keeps its behavior identical to before the column existed.
    const client = await loginAs(operator.username, operator.password);
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "10.9.6.1",
      portSpec: "443",
    });
    expect(res.status).toBe(201);
    expect(res.body.priority).toBe("normal");
    insertedRequestIds.push(res.body.id);
  });
});
