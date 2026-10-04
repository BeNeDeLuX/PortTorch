import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestApiToken, deleteTestAgent, deleteTestApiToken, getApp, type TestAgent, type TestApiToken } from "./helpers";

// POST /api/v1/hosts/cancel-scan finds the running job behind a host's
// claimed scan request. A scanner from 0.28.0 links the two when the job
// starts; an older one does not, and the job is then matched on the
// request's own scanner, target and ports. Both have to keep working,
// since a fleet runs mixed versions.
describe("external API - cancelling a host's running scan", () => {
  let agent: TestAgent;
  let token: TestApiToken;

  beforeAll(async () => {
    agent = await createTestAgent("it-api-cancel");
    token = await createTestApiToken("it-api-cancel");
  });

  afterAll(async () => {
    await db.deleteFrom("scan_requests").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestApiToken(token.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function runningScanFor(ip: string, linked: boolean): Promise<string> {
    const seed = await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${agent.apiKey}`).send({ targetSpec: ip, portSpec: "22" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: seed.body.id, hosts: [{ ip, ports: [{ port: 22, protocol: "tcp", state: "open" }] }] });
    const host = await db.selectFrom("hosts").select("id").where("ip", "=", ip).executeTakeFirstOrThrow();
    const req = await db
      .insertInto("scan_requests")
      .values({ scanner_agent_id: agent.id, host_id: host.id, target_spec: ip, port_spec: "22", status: "claimed", requested_by: "it" })
      .returning("id")
      .executeTakeFirstOrThrow();
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: ip, portSpec: "22", cancellable: true, ...(linked ? { scanRequestId: req.id } : {}) });
    return job.body.id;
  }

  async function cancelRequested(jobId: string): Promise<boolean> {
    const row = await db.selectFrom("scan_jobs").select("cancel_requested_at").where("id", "=", jobId).executeTakeFirstOrThrow();
    return row.cancel_requested_at !== null;
  }

  it("cancels through the link a current scanner makes", async () => {
    const jobId = await runningScanFor("240.95.0.1", true);
    const res = await request(getApp()).post("/api/v1/hosts/cancel-scan").set("Authorization", `Bearer ${token.token}`).send({ ip: "240.95.0.1" });
    expect(res.status).toBe(204);
    expect(await cancelRequested(jobId)).toBe(true);
  });

  it("still finds the job for a scanner too old to link it", async () => {
    const jobId = await runningScanFor("240.95.0.2", false);
    const res = await request(getApp()).post("/api/v1/hosts/cancel-scan").set("Authorization", `Bearer ${token.token}`).send({ ip: "240.95.0.2" });
    expect(res.status).toBe(204);
    expect(await cancelRequested(jobId)).toBe(true);
  });
});
