import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
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

describe("scan schedules - 'once' type", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  const createdIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-schedule-agent");
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await db.deleteFrom("scan_schedules").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    // No closeDb() here - a second describe block below still needs the
    // shared pg pool. Only the last describe block in the file closes it.
  });

  afterEach(async () => {
    while (createdIds.length) {
      await db.deleteFrom("scan_schedules").where("id", "=", createdIds.pop()!).execute();
    }
  });

  it("creates a one-time schedule with the given runAt and no interval/cron fields", async () => {
    const runAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const res = await client.post("/api/schedules").send({
      scheduleType: "once",
      scannerAgentId: agent.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      runAt,
    });
    expect(res.status).toBe(201);
    createdIds.push(res.body.id);

    const list = await client.get("/api/schedules");
    const created = list.body.find((s: { id: string }) => s.id === res.body.id);
    expect(created).toMatchObject({
      schedule_type: "once",
      interval_minutes: null,
      cron_expression: null,
      enabled: true,
    });
    expect(new Date(created.run_at).toISOString()).toBe(runAt);
    expect(new Date(created.next_run_at).toISOString()).toBe(runAt);
  });

  it("rejects a 'once' schedule with no runAt", async () => {
    const res = await client.post("/api/schedules").send({
      scheduleType: "once",
      scannerAgentId: agent.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
    });
    expect(res.status).toBe(400);
  });

  it("rejects intervalMinutes/cronExpression updates against a 'once' schedule", async () => {
    const runAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "once",
      scannerAgentId: agent.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      runAt,
    });
    createdIds.push(createRes.body.id);

    const res = await client.patch(`/api/schedules/${createRes.body.id}`).send({ intervalMinutes: 30 });
    expect(res.status).toBe(400);
  });
});

// Editing scope/ports/scanner/time on an existing schedule, rather than
// only being able to delete and recreate it - covers the fields added
// alongside enabled/intervalMinutes/cronExpression in updateScheduleSchema.
describe("scan schedules - editing", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agentA: TestAgent;
  let agentB: TestAgent;
  const createdIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agentA = await createTestAgent("it-edit-agent-a");
    agentB = await createTestAgent("it-edit-agent-b");
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await db.deleteFrom("scan_schedules").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  afterEach(async () => {
    while (createdIds.length) {
      await db.deleteFrom("scan_schedules").where("id", "=", createdIds.pop()!).execute();
    }
  });

  it("edits targetSpec/portSpec/scannerAgentId on an interval schedule", async () => {
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agentA.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      intervalMinutes: 60,
    });
    createdIds.push(createRes.body.id);

    const patchRes = await client.patch(`/api/schedules/${createRes.body.id}`).send({
      targetSpec: "10.0.0.6",
      portSpec: "443",
      scannerAgentId: agentB.id,
    });
    expect(patchRes.status).toBe(204);

    const list = await client.get("/api/schedules");
    const updated = list.body.find((s: { id: string }) => s.id === createRes.body.id);
    expect(updated).toMatchObject({
      target_spec: "10.0.0.6",
      port_spec: "443",
      scanner_agent_id: agentB.id,
    });
  });

  it("editing runAt on a 'once' schedule moves next_run_at to match", async () => {
    const originalRunAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "once",
      scannerAgentId: agentA.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      runAt: originalRunAt,
    });
    createdIds.push(createRes.body.id);

    const newRunAt = new Date(Date.now() + 2 * 60 * 60_000).toISOString();
    const patchRes = await client.patch(`/api/schedules/${createRes.body.id}`).send({ runAt: newRunAt });
    expect(patchRes.status).toBe(204);

    const list = await client.get("/api/schedules");
    const updated = list.body.find((s: { id: string }) => s.id === createRes.body.id);
    expect(new Date(updated.run_at).toISOString()).toBe(newRunAt);
    expect(new Date(updated.next_run_at).toISOString()).toBe(newRunAt);
  });

  it("rejects a runAt update against a non-'once' schedule", async () => {
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agentA.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      intervalMinutes: 60,
    });
    createdIds.push(createRes.body.id);

    const res = await client
      .patch(`/api/schedules/${createRes.body.id}`)
      .send({ runAt: new Date(Date.now() + 60_000).toISOString() });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown scannerAgentId", async () => {
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agentA.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      intervalMinutes: 60,
    });
    createdIds.push(createRes.body.id);

    const res = await client
      .patch(`/api/schedules/${createRes.body.id}`)
      .send({ scannerAgentId: "00000000-0000-0000-0000-000000000000" });
    expect(res.status).toBe(400);
  });

  it("rejects an empty patch with 'nothing to update'", async () => {
    const createRes = await client.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agentA.id,
      targetSpec: "10.0.0.5",
      portSpec: "80",
      intervalMinutes: 60,
    });
    createdIds.push(createRes.body.id);

    const res = await client.patch(`/api/schedules/${createRes.body.id}`).send({});
    expect(res.status).toBe(400);
  });
});
