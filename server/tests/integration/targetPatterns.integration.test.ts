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

// Address patterns: "every .125 in each /24", "this /16 except .2 and .4",
// as a scan target and as a permanent exclude. The scanner never sees a
// pattern - only the plain list it expands to.
describe("address patterns", () => {
  let a: TestAgent;
  let b: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let op: SessionClient;

  beforeAll(async () => {
    a = await createTestAgent("it-pattern-a");
    b = await createTestAgent("it-pattern-b");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    op = await loginAs(operator.username, operator.password);
  });

  afterAll(async () => {
    await db.deleteFrom("scan_requests").where("scanner_agent_id", "in", [a.id, b.id]).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [a.id, b.id]).execute();
    await db.deleteFrom("scan_schedules").where("scanner_agent_id", "in", [a.id, b.id]).execute();
    await db.deleteFrom("scan_groups").where("target_spec", "like", "10.93.%").execute();
    await db.deleteFrom("scan_excludes").where("value", "like", "10.94.%").execute();
    await deleteTestAgent(a.id);
    await deleteTestAgent(b.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("queues the expansion and keeps the pattern beside it", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentId: a.id, targetSpec: "10.93.*.125", portSpec: "22" });
    expect(res.status).toBe(201);
    const row = await db.selectFrom("scan_requests").select(["target_spec", "target_pattern"]).where("id", "=", res.body.id).executeTakeFirstOrThrow();
    expect(row.target_pattern).toBe("10.93.*.125");
    const all = addresses(row.target_spec);
    expect(all).toHaveLength(256);
    expect(all.every((x) => (x & 255) === 125)).toBe(true);
  });

  it("leaves a target without pattern syntax untouched", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentId: a.id, targetSpec: "10.93.1.0/24", portSpec: "22" });
    const row = await db.selectFrom("scan_requests").select(["target_spec", "target_pattern"]).where("id", "=", res.body.id).executeTakeFirstOrThrow();
    expect(row).toEqual({ target_spec: "10.93.1.0/24", target_pattern: null });
  });

  it("splits the expansion, not the pattern, across several scanners", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentIds: [a.id, b.id], targetSpec: "10.93.0.0/22 !*.2 !*.4", portSpec: "22" });
    expect(res.status).toBe(201);
    const parts = await db.selectFrom("scan_requests").select(["target_spec", "target_pattern"]).where("scan_group_id", "=", res.body.scanGroupId).execute();
    expect(parts).toHaveLength(2);
    const covered = parts.flatMap((p) => addresses(p.target_spec)).sort((x, y) => x - y);
    expect(covered).toHaveLength(1024 - 8);
    expect(covered.some((x) => (x & 255) === 2 || (x & 255) === 4)).toBe(false);
    expect(parts.every((p) => p.target_pattern === "10.93.0.0/22 !*.2 !*.4")).toBe(true);
    const group = await db.selectFrom("scan_groups").select("target_spec").where("id", "=", res.body.scanGroupId).executeTakeFirstOrThrow();
    expect(group.target_spec).toBe("10.93.0.0/22 !*.2 !*.4");
  });

  it("refuses a pattern that cannot be scanned, with the reason", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentId: a.id, targetSpec: "10.93.0.0/30 !*.0-3", portSpec: "22" });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toContain("no address");
  });

  it("estimates the expansion", async () => {
    const res = await op.post("/api/scan-estimate").send({ scannerAgentId: a.id, targetSpec: "10.93.0.0/16 !*.2 !*.4", portSpec: "22" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ addresses: 65536 - 512, expandedFrom: "10.93.0.0/16 !*.2 !*.4" });
    expect((await op.post("/api/scan-estimate").send({ targetSpec: "10.93.0.0/16 !bogus", portSpec: "22" })).status).toBe(400);
  });

  it("keeps the pattern on a schedule and expands it on every run", async () => {
    const created = await adminClient.post("/api/schedules").send({
      scheduleType: "interval",
      intervalMinutes: 60,
      scannerAgentId: a.id,
      targetSpec: "10.93.0-1.125",
      portSpec: "22",
    });
    expect(created.status).toBe(201);
    const stored = await db.selectFrom("scan_schedules").select("target_spec").where("id", "=", created.body.id).executeTakeFirstOrThrow();
    expect(stored.target_spec).toBe("10.93.0-1.125");

    await db.updateTable("scan_schedules").set({ next_run_at: new Date(Date.now() - 1000).toISOString() }).where("id", "=", created.body.id).execute();
    await runSchedulerTick();
    const run = await db.selectFrom("scan_requests").select(["target_spec", "target_pattern"]).where("schedule_id", "=", created.body.id).executeTakeFirstOrThrow();
    expect(run).toEqual({ target_spec: "10.93.0.125,10.93.1.125", target_pattern: "10.93.0-1.125" });

    // A typo fails the save rather than every run after it.
    expect((await adminClient.patch(`/api/schedules/${created.body.id}`).send({ targetSpec: "10.93.0.0/16 !nope" })).status).toBe(400);
  });

  it("shows the pattern in Scan History, where Rescan picks it up", async () => {
    const res = await op.post("/api/adhoc-scans").send({ scannerAgentId: a.id, targetSpec: "10.93.7.1-3", portSpec: "22" });
    const req = await db.selectFrom("scan_requests").select(["id", "target_spec"]).where("id", "=", res.body.id).executeTakeFirstOrThrow();
    const job = await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${a.apiKey}`).send({ targetSpec: req.target_spec, portSpec: "22" });
    await request(getApp()).patch(`/api/ingest/scan-jobs/${job.body.id}`).set("Authorization", `Bearer ${a.apiKey}`).send({ status: "completed" });
    await db.updateTable("scan_requests").set({ scan_job_id: job.body.id, status: "completed" }).where("id", "=", req.id).execute();

    const history = await op.get(`/api/scan-jobs/history?q=${encodeURIComponent("10.93.7.1")}`);
    const entry = history.body.items.find((i: { id: string }) => i.id === job.body.id);
    expect(entry).toMatchObject({ target_pattern: "10.93.7.1-3", target_spec: "10.93.7.1-10.93.7.3" });
  });

  it("serves a pattern exclude to scanners as the addresses it covers", async () => {
    const created = await adminClient.post("/api/excludes").send({ kind: "ip_pattern", value: "10.94.0.0/16   *.2" });
    expect(created.status).toBe(201);
    // Stored with one canonical space, so the same rule typed differently
    // is a duplicate.
    expect(created.body.value).toBe("10.94.0.0/16 *.2");
    expect((await adminClient.post("/api/excludes").send({ kind: "ip_pattern", value: "10.94.0.0/16 *.2" })).status).toBe(409);

    for (const bad of ["10.94.0.0/16", "10.94.0.0/16 10.94.0.2", "10.0.0.0/8 *.2", "web.internal *.2"]) {
      expect((await adminClient.post("/api/excludes").send({ kind: "ip_pattern", value: bad })).status).toBe(400);
    }

    const list = await adminClient.get("/api/excludes");
    expect(list.body.find((e: { id: string }) => e.id === created.body.id).address_count).toBe(256);

    const served = await request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${a.apiKey}`);
    const mine = (served.body.ips as string[]).filter((ip) => ip.startsWith("10.94."));
    expect(mine).toHaveLength(256);
    expect(mine).toContain("10.94.0.2");
    expect(mine).toContain("10.94.255.2");
    expect(mine).not.toContain("10.94.0.3");
  });

  it("splits a pattern through the External API too", async () => {
    const token = await import("./helpers").then((h) => h.createTestApiToken("it-pattern-token"));
    try {
      const res = await request(getApp())
        .post("/api/v1/scans/adhoc")
        .set("Authorization", `Bearer ${token.token}`)
        .send({ scannerAgent: a.name, targetSpec: "10.93.9.*", portSpec: "22" });
      expect(res.status).toBe(201);
      const row = await db.selectFrom("scan_requests").select(["target_spec", "target_pattern"]).where("id", "=", res.body.scanRequestId).executeTakeFirstOrThrow();
      expect(row).toEqual({ target_spec: "10.93.9.0-10.93.9.255", target_pattern: "10.93.9.*" });
    } finally {
      await db.deleteFrom("api_tokens").where("id", "=", token.id).execute();
    }
  });
});
