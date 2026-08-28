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

// The whole point is the round trip: an admin sets a value in the
// dashboard, and the scanner sees it on its own next poll - the webserver
// can never push it. So the assertions follow that path rather than
// stopping at the database row.
describe("dashboard-managed scanner config", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-config-agent");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
  });

  afterEach(async () => {
    await db.updateTable("scanner_agents").set({ config_overrides: null }).where("id", "=", agent.id).execute();
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  function asScanner() {
    return request(getApp()).get("/api/ingest/config").set("Authorization", `Bearer ${agent.apiKey}`);
  }

  it("returns an empty object to a scanner with nothing configured", async () => {
    // The normal case for every agent - and it must not read as an error,
    // or a scanner would treat "no overrides" as a failed fetch.
    const res = await asScanner();
    expect(res.status).toBe(200);
    expect(res.body).toEqual({});
  });

  it("carries an admin's setting through to the scanner's own endpoint", async () => {
    const put = await adminClient.put(`/api/agents/${agent.id}/config`).send({ masscanRate: 250, concurrency: 3 });
    expect(put.status).toBe(200);

    const res = await asScanner();
    expect(res.body).toEqual({ masscanRate: 250, concurrency: 3 });
  });

  it("clears every override when sent an empty object", async () => {
    await adminClient.put(`/api/agents/${agent.id}/config`).send({ masscanRate: 250 });
    expect((await asScanner()).body).toEqual({ masscanRate: 250 });

    const put = await adminClient.put(`/api/agents/${agent.id}/config`).send({});
    expect(put.status).toBe(200);
    expect((await asScanner()).body).toEqual({});
  });

  it("refuses settings that could cut the scanner off, rather than storing them", async () => {
    // These are the ones that would be unfixable remotely: correcting
    // them needs the connection they just broke.
    for (const body of [{ webserverUrl: 1 }, { apiKey: 1 }, { masscanPath: 1 }, { insecureSkipVerify: 1 }]) {
      const res = await adminClient.put(`/api/agents/${agent.id}/config`).send(body);
      expect(res.status).toBe(400);
    }
    expect((await asScanner()).body).toEqual({});
  });

  it("refuses an out-of-range value", async () => {
    const res = await adminClient.put(`/api/agents/${agent.id}/config`).send({ concurrency: 999 });
    expect(res.status).toBe(400);
    expect(res.body.details[0]).toMatchObject({ key: "concurrency" });
    expect((await asScanner()).body).toEqual({});
  });

  it("is admin-only", async () => {
    const res = await operatorClient.put(`/api/agents/${agent.id}/config`).send({ masscanRate: 100 });
    expect(res.status).toBe(403);
  });

  it("serves the tunable allowlist the dashboard builds its form from", async () => {
    // Routed correctly despite sitting alongside /:id/config - a plain
    // /:id route would otherwise swallow this path.
    const res = await operatorClient.get("/api/agents/config/tunables");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const keys = (res.body as Array<{ key: string }>).map((t) => t.key);
    expect(keys).toContain("masscanRate");
    expect(keys).not.toContain("apiKey");
  });

  it("404s for an unknown agent instead of creating anything", async () => {
    const res = await adminClient
      .put("/api/agents/00000000-0000-4000-8000-000000000000/config")
      .send({ masscanRate: 100 });
    expect(res.status).toBe(404);
  });
});
