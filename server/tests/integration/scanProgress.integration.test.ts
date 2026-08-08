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

// Class E (240.0.0.0/4) - reserved, never a real target, so this can't
// collide with genuine data even run against a copy of a real database.
const IP = "240.7.1.1";

describe("scan job progress (PATCH .../progress from the scanner, GET .../progress for the dashboard)", () => {
  let admin: TestUser;
  let restrictedOperator: TestUser;
  let adminClient: SessionClient;
  let restrictedClient: SessionClient;
  let agentA: TestAgent;
  let agentB: TestAgent;
  let jobId: string;

  beforeAll(async () => {
    agentA = await createTestAgent("it-progress-agent-a");
    agentB = await createTestAgent("it-progress-agent-b");

    admin = await createTestUser("admin");
    restrictedOperator = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restrictedOperator.id, scanner_agent_id: agentB.id }).execute();

    adminClient = await loginAs(admin.username, admin.password);
    restrictedClient = await loginAs(restrictedOperator.username, restrictedOperator.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agentA.apiKey}`)
      .send({ targetSpec: IP, portSpec: "22" });
    jobId = jobRes.body.id;
  });

  afterAll(async () => {
    await db.deleteFrom("scan_jobs").where("id", "=", jobId).execute();
    await deleteTestUser(admin.id);
    await deleteTestUser(restrictedOperator.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  it("GET returns nulls/empty before the scanner has pushed anything", async () => {
    const res = await adminClient.get(`/api/scan-jobs/${jobId}/progress`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ currentStage: null, stageDetail: null, logs: [], updatedAt: null });
  });

  it("PATCH from the owning scanner is reflected by GET", async () => {
    const logs = [
      { time: "2026-08-08T14:15:45Z", stage: "masscan", message: "scanning 240.7.1.1 (ports 22)" },
      { time: "2026-08-08T14:16:00Z", stage: "nmap", message: "probing 240.7.1.1 (1 port(s))" },
    ];
    const patchRes = await request(getApp())
      .patch(`/api/ingest/scan-jobs/${jobId}/progress`)
      .set("Authorization", `Bearer ${agentA.apiKey}`)
      .send({ stage: "nmap", stageDetail: "probing 240.7.1.1 (1 port(s))", logs });
    expect(patchRes.status).toBe(204);

    const getRes = await adminClient.get(`/api/scan-jobs/${jobId}/progress`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.currentStage).toBe("nmap");
    expect(getRes.body.stageDetail).toBe("probing 240.7.1.1 (1 port(s))");
    expect(getRes.body.logs).toEqual(logs);
    expect(getRes.body.updatedAt).not.toBeNull();
  });

  it("a second PATCH replaces the log buffer wholesale rather than appending", async () => {
    const newLogs = [{ time: "2026-08-08T14:17:00Z", stage: "submit", message: "submitted 240.7.1.1 (1 open port(s))" }];
    await request(getApp())
      .patch(`/api/ingest/scan-jobs/${jobId}/progress`)
      .set("Authorization", `Bearer ${agentA.apiKey}`)
      .send({ stage: "submit", logs: newLogs });

    const getRes = await adminClient.get(`/api/scan-jobs/${jobId}/progress`);
    expect(getRes.body.currentStage).toBe("submit");
    expect(getRes.body.logs).toEqual(newLogs);
  });

  it("PATCH is rejected for a job that belongs to a different scanner agent", async () => {
    const res = await request(getApp())
      .patch(`/api/ingest/scan-jobs/${jobId}/progress`)
      .set("Authorization", `Bearer ${agentB.apiKey}`)
      .send({ stage: "nmap", logs: [] });
    expect(res.status).toBe(404);
  });

  it("PATCH requires a valid scanner api key", async () => {
    const res = await request(getApp())
      .patch(`/api/ingest/scan-jobs/${jobId}/progress`)
      .send({ stage: "nmap", logs: [] });
    expect(res.status).toBe(401);
  });

  it("GET requires authentication", async () => {
    const res = await request(getApp()).get(`/api/scan-jobs/${jobId}/progress`);
    expect(res.status).toBe(401);
  });

  it("a restricted operator (scoped to a different scanner) gets 404 for this job's progress", async () => {
    const res = await restrictedClient.get(`/api/scan-jobs/${jobId}/progress`);
    expect(res.status).toBe(404);
  });

  it("GET 400s on a malformed job id", async () => {
    const res = await adminClient.get("/api/scan-jobs/not-a-uuid/progress");
    expect(res.status).toBe(400);
  });
});
