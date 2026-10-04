import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { parseTargetSpecRanges } from "../../src/lib/ipRange";
import { runSchedulerTick } from "../../src/scheduler";
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

function addresses(spec: string): number[] {
  const out: number[] = [];
  for (const r of parseTargetSpecRanges(spec) ?? []) for (let a = r.start; a <= r.end; a++) out.push(a);
  return out;
}

// One scan split across several scanners: the target divided between
// them, each share its own queue entry, the same address always on the
// same scanner.
describe("scans split across several scanners", () => {
  let a: TestAgent;
  let b: TestAgent;
  let c: TestAgent;
  let outside: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let restricted: TestUser;
  let adminClient: SessionClient;
  let op: SessionClient;
  let scoped: SessionClient;

  beforeAll(async () => {
    a = await createTestAgent("it-split-a");
    b = await createTestAgent("it-split-b");
    c = await createTestAgent("it-split-c");
    outside = await createTestAgent("it-split-outside");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    restricted = await createTestUser("operator");
    await db
      .insertInto("user_scanner_agents")
      .values([
        { user_id: restricted.id, scanner_agent_id: a.id },
        { user_id: restricted.id, scanner_agent_id: b.id },
      ])
      .execute();
    adminClient = await loginAs(admin.username, admin.password);
    op = await loginAs(operator.username, operator.password);
    scoped = await loginAs(restricted.username, restricted.password);
  });

  afterAll(async () => {
    const ids = [a.id, b.id, c.id, outside.id];
    await db.deleteFrom("scan_requests").where("scanner_agent_id", "in", ids).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", ids).execute();
    await db.deleteFrom("scan_schedules").where("scanner_agent_id", "in", ids).execute();
    await db.deleteFrom("scan_groups").where("target_spec", "like", "240.91.%").execute();
    for (const agent of [a, b, c, outside]) await deleteTestAgent(agent.id);
    for (const u of [admin, operator, restricted]) await deleteTestUser(u.id);
    await closeDb();
  });

  async function partsOf(groupId: string) {
    return db
      .selectFrom("scan_requests")
      .select(["scanner_agent_id", "target_spec", "masscan_rate", "group_part", "group_parts", "status"])
      .where("scan_group_id", "=", groupId)
      .orderBy("group_part")
      .execute();
  }

  it("leaves a single-scanner scan exactly as it always was", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentId: a.id, targetSpec: "240.91.0.0/24", portSpec: "22" });
    expect(res.status).toBe(201);
    expect(res.body.scanGroupId).toBeNull();
    const row = await db.selectFrom("scan_requests").selectAll().where("id", "=", res.body.id).executeTakeFirstOrThrow();
    expect(row).toMatchObject({ target_spec: "240.91.0.0/24", scan_group_id: null, group_part: null });
  });

  it("divides the target between the scanners, every address exactly once", async () => {
    const res = await op
      .post("/api/adhoc-scans")
      .send({ scannerAgentIds: [a.id, b.id, c.id], targetSpec: "240.91.1.0/24", portSpec: "22,443", masscanRate: 3000, masscanRateSplit: true, tags: ["it-split"] });
    expect(res.status).toBe(201);
    expect(res.body.scanGroupId).toBeTruthy();
    expect(res.body.parts).toHaveLength(3);

    const parts = await partsOf(res.body.scanGroupId);
    expect(parts.map((p) => p.group_part)).toEqual([1, 2, 3]);
    expect(new Set(parts.map((p) => p.scanner_agent_id))).toEqual(new Set([a.id, b.id, c.id]));
    for (const p of parts) {
      expect(p).toMatchObject({ group_parts: 3, status: "pending", masscan_rate: 1000 });
    }
    const covered = parts.flatMap((p) => addresses(p.target_spec)).sort((x, y) => x - y);
    expect(covered).toEqual(addresses("240.91.1.0/24"));

    const group = await db.selectFrom("scan_groups").selectAll().where("id", "=", res.body.scanGroupId).executeTakeFirstOrThrow();
    expect(group).toMatchObject({ target_spec: "240.91.1.0/24", port_spec: "22,443", parts: 3, masscan_rate_split: true, requested_by: operator.username });
  });

  it("gives every address the same scanner on the next run", async () => {
    // The property that keeps host identity stable from one scan to the
    // next - and so keeps duplicate host rows from appearing.
    const first = await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.2.0/24", portSpec: "22" });
    const second = await op.post("/api/adhoc-scans").send({ scannerAgentIds: [b.id, a.id], targetSpec: "240.91.2.0/24", portSpec: "22" });
    const byScanner = async (groupId: string) =>
      Object.fromEntries((await partsOf(groupId)).map((p) => [p.scanner_agent_id, p.target_spec]));
    expect(await byScanner(second.body.scanGroupId)).toEqual(await byScanner(first.body.scanGroupId));
  });

  it("keeps each scanner at its full rate unless asked to divide it", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.3.0/24", portSpec: "22", masscanRate: 500 });
    for (const p of await partsOf(res.body.scanGroupId)) expect(p.masscan_rate).toBe(500);
  });

  it("refuses what it cannot honour", async () => {
    // A divided rate needs a rate to divide.
    expect(
      (await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.4.0/24", portSpec: "22", masscanRateSplit: true })).status
    ).toBe(400);
    // A restricted operator cannot pull an out-of-scope scanner into a split.
    expect(
      (await scoped.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, outside.id], targetSpec: "240.91.4.0/24", portSpec: "22" })).status
    ).toBe(403);
    expect((await scoped.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.4.0/24", portSpec: "22" })).status).toBe(201);
    // A revoked scanner would never claim its share.
    await db.updateTable("scanner_agents").set({ revoked_at: new Date() }).where("id", "=", c.id).execute();
    try {
      expect((await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, c.id], targetSpec: "240.91.4.0/24", portSpec: "22" })).status).toBe(400);
    } finally {
      await db.updateTable("scanner_agents").set({ revoked_at: null }).where("id", "=", c.id).execute();
    }
    // Neither scanner field at all.
    expect((await op.post("/api/adhoc-scans").send({ targetSpec: "240.91.4.0/24", portSpec: "22" })).status).toBe(400);
  });

  it("estimates per scanner, with the scan taking as long as its slowest part", async () => {
    const res = await op
      .post("/api/scan-estimate")
      .send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.0.0/22", portSpec: "1-100", masscanRate: 1000, masscanRateSplit: false });
    expect(res.status).toBe(200);
    expect(res.body.addresses).toBe(1024);
    expect(res.body.parts).toHaveLength(2);
    expect(res.body.parts.reduce((n: number, p: { addresses: number }) => n + p.addresses, 0)).toBe(1024);
    for (const p of res.body.parts) expect(p.masscanSeconds).toBeLessThan(res.body.masscanSeconds);
  });

  it("splits every run of a schedule, and skips a run while the last is still queued", async () => {
    const created = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      intervalMinutes: 60,
      scannerAgentIds: [a.id, b.id],
      targetSpec: "240.91.8.0/24",
      portSpec: "22",
    });
    expect(created.status).toBe(201);
    await db.updateTable("scan_schedules").set({ next_run_at: new Date(Date.now() - 1000).toISOString() }).where("id", "=", created.body.id).execute();

    await runSchedulerTick();
    const queued = await db.selectFrom("scan_requests").selectAll().where("schedule_id", "=", created.body.id).execute();
    expect(queued).toHaveLength(2);
    expect(new Set(queued.map((q) => q.scanner_agent_id))).toEqual(new Set([a.id, b.id]));
    expect(queued.every((q) => q.scan_group_id === queued[0].scan_group_id && q.requested_by === "schedule")).toBe(true);

    // Due again while both parts still wait: skipped, not stacked.
    await db.updateTable("scan_schedules").set({ next_run_at: new Date(Date.now() - 1000).toISOString() }).where("id", "=", created.body.id).execute();
    await runSchedulerTick();
    expect(await db.selectFrom("scan_requests").select("id").where("schedule_id", "=", created.body.id).execute()).toHaveLength(2);

    const list = await adminClient.get("/api/schedules");
    const mine = list.body.find((s: { id: string }) => s.id === created.body.id);
    expect(mine.scanner_agent_ids).toEqual([a.id, b.id]);
    expect(mine.scanner_agent_names).toHaveLength(2);
  });

  it("hands a revoked scanner's share of a schedule to the others", async () => {
    const created = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      intervalMinutes: 60,
      scannerAgentIds: [a.id, c.id],
      targetSpec: "240.91.9.0/24",
      portSpec: "22",
    });
    expect(created.status).toBe(201);
    await db.updateTable("scanner_agents").set({ revoked_at: new Date() }).where("id", "=", c.id).execute();
    try {
      await db.updateTable("scan_schedules").set({ next_run_at: new Date(Date.now() - 1000).toISOString() }).where("id", "=", created.body.id).execute();
      await runSchedulerTick();
      const queued = await db.selectFrom("scan_requests").selectAll().where("schedule_id", "=", created.body.id).execute();
      expect(queued).toHaveLength(1);
      expect(queued[0]).toMatchObject({ scanner_agent_id: a.id, target_spec: "240.91.9.0/24", scan_group_id: null });
    } finally {
      await db.updateTable("scanner_agents").set({ revoked_at: null }).where("id", "=", c.id).execute();
    }
  });

  it("refuses a schedule whose split cannot be honoured, and can turn a split back into one scanner", async () => {
    const bad = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      intervalMinutes: 60,
      scannerAgentIds: [a.id, b.id],
      masscanRateSplit: true,
      targetSpec: "240.91.10.0/24",
      portSpec: "22",
    });
    expect(bad.status).toBe(400);

    const created = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      intervalMinutes: 60,
      scannerAgentIds: [a.id, b.id],
      targetSpec: "240.91.10.0/24",
      portSpec: "22",
    });
    const patched = await adminClient.patch(`/api/schedules/${created.body.id}`).send({ scannerAgentIds: [b.id] });
    expect(patched.status).toBe(204);
    const row = await db.selectFrom("scan_schedules").select(["scanner_agent_id", "scanner_agent_ids"]).where("id", "=", created.body.id).executeTakeFirstOrThrow();
    expect(row).toEqual({ scanner_agent_id: b.id, scanner_agent_ids: null });
  });

  it("shows each finished share in Scan History as a part of the whole", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "240.91.11.0/24", portSpec: "22" });
    const part = (await partsOf(res.body.scanGroupId))[0];
    const agent = part.scanner_agent_id === a.id ? a : b;
    // What the scanner does with its share: run it as a job, then report
    // the request done with that job's id.
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: part.target_spec, portSpec: "22" });
    await request(getApp()).patch(`/api/ingest/scan-jobs/${job.body.id}`).set("Authorization", `Bearer ${agent.apiKey}`).send({ status: "completed" });
    await db.updateTable("scan_requests").set({ scan_job_id: job.body.id, status: "completed" }).where("scan_group_id", "=", res.body.scanGroupId).where("scanner_agent_id", "=", agent.id).execute();

    const history = await op.get(`/api/scan-jobs/history?q=${encodeURIComponent(part.target_spec.split(",")[0])}`);
    const entry = history.body.items.find((i: { id: string }) => i.id === job.body.id);
    expect(entry).toMatchObject({ group_part: part.group_part, group_parts: 2, group_target_spec: "240.91.11.0/24" });
    expect(new Set(entry.group_scanner_agent_ids)).toEqual(new Set([a.id, b.id]));
  });
});
