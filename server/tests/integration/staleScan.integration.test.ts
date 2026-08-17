import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  loginAs,
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

// Confirms the real-world case this feature exists for: a scan that's
// simply slow (e.g. masscan's own single, unstreamable pass across a
// large target range) must not be flagged stale as long as the scanner
// process is still demonstrably alive and pushing its periodic progress
// heartbeat - only a scan with no heartbeat for the configured threshold
// is. Exercises the real GET /api/scan-jobs/active route end-to-end
// against a real database, not just isStaleScanJob in isolation.
describe("scan staleness - activity-aware", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  const createdJobIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-stale-scan-agent");
  });

  afterAll(async () => {
    for (const id of createdJobIds) {
      await db.deleteFrom("scan_jobs").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
  });

  it("a running scan with an old started_at but a recent progress heartbeat is NOT stale", async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60_000).toISOString();
    const job = await db
      .insertInto("scan_jobs")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "240.9.5.1",
        port_spec: "1-1000",
        status: "running",
        started_at: twoHoursAgo,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    createdJobIds.push(job.id);

    await db
      .insertInto("scan_job_progress")
      .values({
        scan_job_id: job.id,
        current_stage: "masscan",
        stage_detail: "scanning 240.9.5.0/24 (ports 1-1000)",
        recent_logs: JSON.stringify([]),
        updated_at: new Date().toISOString(),
      })
      .execute();

    const res = await client.get("/api/scan-jobs/active");
    expect(res.status).toBe(200);
    const found = res.body.find((j: { id: string }) => j.id === job.id);
    expect(found).toBeDefined();
    expect(found.is_stale).toBe(false);
  });

  it("a running scan with an old started_at and no progress heartbeat IS stale", async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60_000).toISOString();
    const job = await db
      .insertInto("scan_jobs")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "240.9.5.2",
        port_spec: "1-1000",
        status: "running",
        started_at: twoHoursAgo,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    createdJobIds.push(job.id);
    // Deliberately no scan_job_progress row - simulates a scanner process
    // that died before its very first push, or long enough ago that its
    // last push is itself now past the threshold (same effective case,
    // since isStaleScanJob falls back to started_at either way).

    const res = await client.get("/api/scan-jobs/active");
    expect(res.status).toBe(200);
    const found = res.body.find((j: { id: string }) => j.id === job.id);
    expect(found).toBeDefined();
    expect(found.is_stale).toBe(true);
  });

  it("a running scan with an old started_at and an equally old progress heartbeat IS stale - the scanner actually died", async () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60_000).toISOString();
    const job = await db
      .insertInto("scan_jobs")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "240.9.5.3",
        port_spec: "1-1000",
        status: "running",
        started_at: twoHoursAgo,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    createdJobIds.push(job.id);

    await db
      .insertInto("scan_job_progress")
      .values({
        scan_job_id: job.id,
        current_stage: "nmap",
        stage_detail: "probing 240.9.5.3",
        recent_logs: JSON.stringify([]),
        updated_at: twoHoursAgo,
      })
      .execute();

    const res = await client.get("/api/scan-jobs/active");
    expect(res.status).toBe(200);
    const found = res.body.find((j: { id: string }) => j.id === job.id);
    expect(found).toBeDefined();
    expect(found.is_stale).toBe(true);
  });
});

describe("settings - stale scan threshold", () => {
  let admin: TestUser;
  let client: SessionClient;
  let originalValue: number;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    const current = await client.get("/api/settings/app");
    originalValue = current.body.staleScanThresholdMinutes;
  });

  afterAll(async () => {
    await client.patch("/api/settings/app").send({ staleScanThresholdMinutes: originalValue });
    await deleteTestUser(admin.id);
    await closeDb();
  });

  it("is live-editable and reflected on the next read", async () => {
    const patchRes = await client.patch("/api/settings/app").send({ staleScanThresholdMinutes: 15 });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body.staleScanThresholdMinutes).toBe(15);

    const getRes = await client.get("/api/settings/app");
    expect(getRes.body.staleScanThresholdMinutes).toBe(15);
  });

  it("rejects a non-positive value", async () => {
    const res = await client.patch("/api/settings/app").send({ staleScanThresholdMinutes: 0 });
    expect(res.status).toBe(400);
  });
});
