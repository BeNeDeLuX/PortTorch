import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { runRetentionSweep } from "../../src/retention";
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

// scan_job_full_log and scan_job_progress were the only tables in the
// schema with no bound at all - retention knew about hosts and audit_log,
// and nothing has ever deleted a scan_jobs row, so their ON DELETE
// CASCADE never fired. Measured against real jsonb these are also the
// largest rows in the database.
describe("scan log retention", () => {
  let agent: TestAgent;
  const jobIds: string[] = [];

  afterAll(async () => {
    for (const id of jobIds) await db.deleteFrom("scan_jobs").where("id", "=", id).execute();
    if (agent) await deleteTestAgent(agent.id);
  });

  async function makeJob(status: string, ageDays: number): Promise<string> {
    if (!agent) agent = await createTestAgent("it-scanlog-agent");
    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: "240.41.0.1", port_spec: "1-100", status })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    jobIds.push(job.id);

    const at = new Date(Date.now() - ageDays * 86_400_000);
    await db
      .insertInto("scan_job_progress")
      .values({ scan_job_id: job.id, current_stage: "nmap", recent_logs: JSON.stringify([]), updated_at: at })
      .execute();
    await db
      .insertInto("scan_job_full_log")
      .values({ scan_job_id: job.id, logs: JSON.stringify([{ time: at, stage: "nmap", message: "x" }]), created_at: at })
      .execute();
    return job.id;
  }

  const logsFor = async (jobId: string) => ({
    progress: await db.selectFrom("scan_job_progress").select(["scan_job_id"]).where("scan_job_id", "=", jobId).executeTakeFirst(),
    full: await db.selectFrom("scan_job_full_log").select(["scan_job_id"]).where("scan_job_id", "=", jobId).executeTakeFirst(),
  });

  it("purges logs past the window but keeps the scan_jobs row itself", async () => {
    await db.updateTable("app_settings").set({ scan_log_retention_days: 30 }).where("id", "=", 1).execute();
    const old = await makeJob("completed", 45);
    const recent = await makeJob("completed", 2);

    const result = await runRetentionSweep();
    expect(result.purgedScanLogs).toBeGreaterThanOrEqual(2);

    // The old job's logs are gone...
    const oldLogs = await logsFor(old);
    expect(oldLogs.progress).toBeUndefined();
    expect(oldLogs.full).toBeUndefined();

    // ...but Scan History still has the scan itself, which is the whole
    // point of purging the logs rather than the job.
    const job = await db.selectFrom("scan_jobs").select(["id", "target_spec"]).where("id", "=", old).executeTakeFirst();
    expect(job?.target_spec).toBe("240.41.0.1");

    // And a recent scan is untouched.
    const recentLogs = await logsFor(recent);
    expect(recentLogs.progress).toBeDefined();
    expect(recentLogs.full).toBeDefined();
  });

  // A very large scan can legitimately outrun the window; deleting its
  // live progress would empty the Details popup mid-scan.
  it("never touches a scan that is still running", async () => {
    await db.updateTable("app_settings").set({ scan_log_retention_days: 30 }).where("id", "=", 1).execute();
    const running = await makeJob("running", 90);

    await runRetentionSweep();

    const logs = await logsFor(running);
    expect(logs.progress).toBeDefined();
    expect(logs.full).toBeDefined();
  });

  it("is disabled at 0, and runs independently of the host retention window", async () => {
    await db.updateTable("app_settings").set({ scan_log_retention_days: 0 }).where("id", "=", 1).execute();
    const old = await makeJob("completed", 400);
    expect((await runRetentionSweep()).purgedScanLogs).toBe(0);
    expect((await logsFor(old)).full).toBeDefined();

    // Host retention off, scan-log retention on: the logs must still be
    // bounded. Folding both under one early return would silently
    // reintroduce the unbounded growth this exists to fix.
    await db
      .updateTable("app_settings")
      .set({ host_retention_days: 0, scan_log_retention_days: 30 })
      .where("id", "=", 1)
      .execute();
    expect((await runRetentionSweep()).purgedScanLogs).toBeGreaterThanOrEqual(1);
    expect((await logsFor(old)).full).toBeUndefined();

    await db.updateTable("app_settings").set({ host_retention_days: 180 }).where("id", "=", 1).execute();
  });
});

describe("session management", () => {
  const created: number[] = [];

  afterAll(async () => {
    for (const id of created) await deleteTestUser(id);
    await closeDb();
  });

  async function user(role: "admin" | "operator" | "user" = "operator"): Promise<TestUser> {
    const u = await createTestUser(role);
    created.push(u.id);
    return u;
  }

  it("signs out other sessions on request, keeping the caller's own", async () => {
    const u = await user();
    const other = await loginAs(u.username, u.password);
    const mine = await loginAs(u.username, u.password);
    expect((await other.get("/auth/me")).status).toBe(200);

    const res = await mine.post("/auth/sessions/revoke-others");
    expect(res.status).toBe(200);
    expect(res.body.revoked).toBeGreaterThanOrEqual(1);

    expect((await other.get("/auth/me")).status).toBe(401);
    expect((await mine.get("/auth/me")).status).toBe(200);
  });

  it("reports each account's active session count to admins", async () => {
    const target = await user();
    await loginAs(target.username, target.password);
    await loginAs(target.username, target.password);

    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);
    const list = await adminSession.get("/api/users");
    const row = list.body.find((u: { id: number }) => u.id === target.id);
    expect(row.activeSessions).toBe(2);
  });

  it("lets an admin end another account's sessions without touching credentials", async () => {
    const target = await user();
    const targetSession = await loginAs(target.username, target.password);
    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);

    const res = await adminSession.post(`/api/users/${target.id}/revoke-sessions`);
    expect(res.status).toBe(200);
    expect(res.body.revoked).toBeGreaterThanOrEqual(1);
    expect((await targetSession.get("/auth/me")).status).toBe(401);

    // Their password still works - this ends sessions, it doesn't lock
    // the account.
    const relogin = await request(getApp())
      .post("/auth/login")
      .set("X-Forwarded-Proto", "https")
      .send({ username: target.username, password: target.password });
    expect(relogin.status).toBe(200);
  });

  it("is admin-only, and 404s an unknown user", async () => {
    const operator = await user("operator");
    const opSession = await loginAs(operator.username, operator.password);
    expect((await opSession.post(`/api/users/${operator.id}/revoke-sessions`)).status).toBe(403);

    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);
    expect((await adminSession.post("/api/users/999999/revoke-sessions")).status).toBe(404);
  });
});
