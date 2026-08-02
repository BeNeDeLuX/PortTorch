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

interface QueueRow {
  id: string;
}

// Covers the scan_requests queue's pending -> cancelled transition (the
// "Queued" section on Scanner Agents / POST /api/scan-jobs/queue/:id/cancel)
// end to end: the row disappears from the operator-facing queue view AND
// from the scanner's own claim query, which is the part that actually
// matters (a cancelled request must never be picked up and run).
describe("scan request queue", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let readOnlyUser: TestUser;

  beforeAll(async () => {
    agent = await createTestAgent();
    operator = await createTestUser("operator");
    readOnlyUser = await createTestUser("user");
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(operator.id);
    await deleteTestUser(readOnlyUser.id);
    await closeDb();
  });

  const insertedRequestIds: string[] = [];

  afterEach(async () => {
    while (insertedRequestIds.length) {
      await db.deleteFrom("scan_requests").where("id", "=", insertedRequestIds.pop()!).execute();
    }
  });

  async function insertPendingScanRequest(): Promise<string> {
    const row = await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "10.0.0.0/24",
        port_spec: "1-1000",
        status: "pending",
        requested_by: "integration-test",
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    insertedRequestIds.push(row.id);
    return row.id;
  }

  it("shows a pending request in the queue view", async () => {
    const id = await insertPendingScanRequest();
    const client = await loginAs(operator.username, operator.password);

    const res = await client.get("/api/scan-jobs/queue");

    expect(res.status).toBe(200);
    expect((res.body as QueueRow[]).some((r) => r.id === id)).toBe(true);
  });

  it("lets an operator cancel a pending request, removing it from the queue and the scanner's own claim query", async () => {
    const id = await insertPendingScanRequest();
    const client = await loginAs(operator.username, operator.password);

    const cancelRes = await client.post(`/api/scan-jobs/queue/${id}/cancel`);
    expect(cancelRes.status).toBe(204);

    const queueRes = await client.get("/api/scan-jobs/queue");
    expect((queueRes.body as QueueRow[]).some((r) => r.id === id)).toBe(false);

    const row = await db.selectFrom("scan_requests").select(["status"]).where("id", "=", id).executeTakeFirstOrThrow();
    expect(row.status).toBe("cancelled");

    // The scanner's own claim query filters on status = 'pending' - this
    // is the part that actually prevents a cancelled request from being
    // run, not just from being displayed.
    const claimRes = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${agent.apiKey}`);
    expect(claimRes.status).toBe(204);
  });

  it("rejects a read-only user from cancelling a pending request", async () => {
    const id = await insertPendingScanRequest();
    const client = await loginAs(readOnlyUser.username, readOnlyUser.password);

    const res = await client.post(`/api/scan-jobs/queue/${id}/cancel`);
    expect(res.status).toBe(403);

    const row = await db.selectFrom("scan_requests").select(["status"]).where("id", "=", id).executeTakeFirstOrThrow();
    expect(row.status).toBe("pending");
  });

  it("returns 409 when cancelling a request that's no longer pending", async () => {
    const id = await insertPendingScanRequest();
    const client = await loginAs(operator.username, operator.password);

    const firstRes = await client.post(`/api/scan-jobs/queue/${id}/cancel`);
    expect(firstRes.status).toBe(204);

    const secondRes = await client.post(`/api/scan-jobs/queue/${id}/cancel`);
    expect(secondRes.status).toBe(409);
  });

  it("returns 404 for an unknown request id", async () => {
    const client = await loginAs(operator.username, operator.password);
    const res = await client.post("/api/scan-jobs/queue/00000000-0000-0000-0000-000000000000/cancel");
    expect(res.status).toBe(404);
  });
});
