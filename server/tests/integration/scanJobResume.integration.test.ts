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

// A scan that stopped early used to have exactly one way back: run the
// whole thing again. The scanner now reports what it never finished, and
// the dashboard can queue only that.
describe("resuming a scan that stopped early", () => {
  let agent: TestAgent;
  let otherAgent: TestAgent;
  let operator: TestUser;
  let viewer: TestUser;
  let restricted: TestUser;
  let op: SessionClient;
  let view: SessionClient;
  let scoped: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-resume");
    otherAgent = await createTestAgent("it-resume-other");
    operator = await createTestUser("operator");
    viewer = await createTestUser("user");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: otherAgent.id }).execute();
    op = await loginAs(operator.username, operator.password);
    view = await loginAs(viewer.username, viewer.password);
    scoped = await loginAs(restricted.username, restricted.password);
  });

  afterAll(async () => {
    await db.updateTable("scan_jobs").set({ resumed_scan_request_id: null }).where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_requests").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(otherAgent.id);
    await deleteTestUser(operator.id);
    await deleteTestUser(viewer.id);
    await deleteTestUser(restricted.id);
    await closeDb();
  });

  async function finishedJob(status: "completed" | "cancelled" | "failed", remaining?: string): Promise<string> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.35.0.0/22", portSpec: "22,443", cancellable: true });
    expect(job.status).toBe(201);
    const patch = await request(getApp())
      .patch(`/api/ingest/scan-jobs/${job.body.id}`)
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ status, ...(remaining ? { remainingTargetSpec: remaining } : {}) });
    expect(patch.status).toBe(204);
    return job.body.id;
  }

  async function row(id: string) {
    return db
      .selectFrom("scan_jobs")
      .select(["remaining_target_spec", "resumed_at", "resumed_scan_request_id"])
      .where("id", "=", id)
      .executeTakeFirstOrThrow();
  }

  it("stores the remainder of a cancelled scan and never of a completed one", async () => {
    const cancelled = await finishedJob("cancelled", "240.35.1.0-240.35.3.255");
    expect((await row(cancelled)).remaining_target_spec).toBe("240.35.1.0-240.35.3.255");

    // A completed scan has nothing left by definition, whatever the
    // payload claims.
    const completed = await finishedJob("completed", "240.35.9.9");
    expect((await row(completed)).remaining_target_spec).toBeNull();

    const history = await op.get("/api/scan-jobs/history?q=240.35.0.0");
    const entry = history.body.items.find((i: { id: string }) => i.id === cancelled);
    expect(entry.remaining_target_spec).toBe("240.35.1.0-240.35.3.255");
    expect(entry.resumed_at).toBeNull();
  });

  it("queues only the remainder, with the original request's settings", async () => {
    const jobId = await finishedJob("cancelled", "240.35.1.0-240.35.3.255");
    // The request that ran it, as the queue loop leaves it once the scan
    // is over - carrying the snapshot the resume must reuse.
    await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: agent.id,
        host_id: null,
        target_spec: "240.35.0.0/22",
        port_spec: "22,443",
        status: "cancelled",
        scan_job_id: jobId,
        requested_by: "it",
        nse_profile: "all_safe",
        nse_profile_label: "All Safe Modules",
        nuclei_profile: "safe",
        nuclei_tags: ["dos", "fuzz", "intrusive"],
        nuclei_profile_label: "Safe",
        masscan_rate: 50,
        priority: "low",
        tags: ["it-resume-tag"],
      })
      .execute();

    const res = await op.post(`/api/scan-jobs/${jobId}/resume`);
    expect(res.status).toBe(201);
    expect(res.body.targetSpec).toBe("240.35.1.0-240.35.3.255");

    const queued = await db
      .selectFrom("scan_requests")
      .selectAll()
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(queued).toMatchObject({
      scanner_agent_id: agent.id,
      target_spec: "240.35.1.0-240.35.3.255",
      port_spec: "22,443",
      status: "pending",
      requested_by: operator.username,
      nse_profile: "all_safe",
      nuclei_profile: "safe",
      masscan_rate: 50,
      priority: "low",
      tags: ["it-resume-tag"],
    });

    const after = await row(jobId);
    expect(after.resumed_at).not.toBeNull();
    expect(after.resumed_scan_request_id).toBe(res.body.scanRequestId);

    // A second click - or a second operator - must not queue it twice.
    expect((await op.post(`/api/scan-jobs/${jobId}/resume`)).status).toBe(409);
    const count = await db
      .selectFrom("scan_requests")
      .select(({ fn }) => fn.countAll<number>().as("n"))
      .where("target_spec", "=", "240.35.1.0-240.35.3.255")
      .executeTakeFirstOrThrow();
    expect(Number(count.n)).toBe(1);
  });

  it("falls back to defaults when no queued request started the scan", async () => {
    const jobId = await finishedJob("failed", "240.35.2.7");
    const res = await op.post(`/api/scan-jobs/${jobId}/resume`);
    expect(res.status).toBe(201);
    const queued = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nuclei_profile", "priority", "tags", "masscan_rate"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(queued).toEqual({ nse_profile: "default", nuclei_profile: "off", priority: "normal", tags: null, masscan_rate: null });
  });

  it("refuses a scan with nothing left, a read-only user, and a scanner outside the caller's scope", async () => {
    const nothing = await finishedJob("cancelled");
    expect((await op.post(`/api/scan-jobs/${nothing}/resume`)).status).toBe(409);

    const jobId = await finishedJob("cancelled", "240.35.3.3");
    expect((await view.post(`/api/scan-jobs/${jobId}/resume`)).status).toBe(403);
    // 404 rather than 403, so an out-of-scope job's existence is not
    // confirmed - the same rule every other scan-job action follows.
    expect((await scoped.post(`/api/scan-jobs/${jobId}/resume`)).status).toBe(404);
    expect((await row(jobId)).resumed_at).toBeNull();
  });

  it("refuses to resume on a revoked scanner", async () => {
    const jobId = await finishedJob("cancelled", "240.35.3.4");
    await db.updateTable("scanner_agents").set({ revoked_at: new Date() }).where("id", "=", agent.id).execute();
    try {
      expect((await op.post(`/api/scan-jobs/${jobId}/resume`)).status).toBe(409);
    } finally {
      await db.updateTable("scanner_agents").set({ revoked_at: null }).where("id", "=", agent.id).execute();
    }
  });
});
