import fs from "fs";
import path from "path";
import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { config } from "../../src/config";
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

// Nothing in this codebase ever unlinked a screenshot. Every capture
// writes a fresh <uuid>.png, and deleting a host cascaded its rows away
// while leaving the files behind referenced by nothing - the database
// shrank, the disk never did. These tests assert against the real
// filesystem, because "the row is gone" was never the part that was
// broken.
describe("screenshot file cleanup", () => {
  let agent: TestAgent;
  let admin: TestUser;
  const hostIps: string[] = [];
  const created: number[] = [];

  afterAll(async () => {
    for (const ip of hostIps) await db.deleteFrom("hosts").where("ip", "=", ip).execute();
    if (agent) await deleteTestAgent(agent.id);
    for (const id of created) await deleteTestUser(id);
    await closeDb();
  });

  let scanJobId: string;

  async function setup(): Promise<void> {
    if (!agent) agent = await createTestAgent("it-shots-agent");
    if (!scanJobId) {
      const job = await db
        .insertInto("scan_jobs")
        .values({ scanner_agent_id: agent.id, target_spec: "240.51.0.0/24", port_spec: "1-100", status: "completed" })
        .returning(["id"])
        .executeTakeFirstOrThrow();
      scanJobId = job.id;
    }
    if (!admin) {
      admin = await createTestUser("admin");
      created.push(admin.id);
    }
    fs.mkdirSync(path.resolve(config.screenshotDir), { recursive: true });
  }

  // Writes a real file and a row pointing at it, the same shape ingest
  // produces - going through the upload endpoint would need a real PNG
  // and adds nothing to what's under test here.
  async function makeHostWithScreenshot(ip: string, capturedAt = new Date()): Promise<{ hostId: string; file: string }> {
    await setup();
    hostIps.push(ip);
    const host = await db
      .insertInto("hosts")
      .values({ ip, scanner_agent_id: agent.id, first_seen_at: new Date(), last_seen_at: capturedAt })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    const file = path.join(path.resolve(config.screenshotDir), `it-${Math.random().toString(16).slice(2)}.png`);
    fs.writeFileSync(file, "not-really-a-png");
    await db
      .insertInto("screenshots")
      .values({ host_id: host.id, scan_job_id: scanJobId, port: 443, url: `https://${ip}/`, image_path: file, captured_at: capturedAt })
      .execute();
    return { hostId: host.id, file };
  }

  it("removes the file when an admin deletes the host", async () => {
    const { hostId, file } = await makeHostWithScreenshot("240.51.0.1");
    expect(fs.existsSync(file)).toBe(true);

    const session = await loginAs(admin.username, admin.password);
    expect((await session.delete(`/api/hosts/${hostId}`)).status).toBe(204);

    expect(fs.existsSync(file)).toBe(false);
  });

  it("removes the file when retention purges the host", async () => {
    // last_seen_at well past the window, so the host sweep takes it.
    const old = new Date(Date.now() - 400 * 86_400_000);
    const { file } = await makeHostWithScreenshot("240.51.0.2", old);
    await db.updateTable("app_settings").set({ host_retention_days: 180 }).where("id", "=", 1).execute();

    const result = await runRetentionSweep();
    expect(result.purgedHosts).toBeGreaterThanOrEqual(1);
    expect(fs.existsSync(file)).toBe(false);
  });

  // Without this only host deletion ever reclaims anything, so a
  // long-lived host scanned on a schedule grows without limit.
  it("purges old captures of a host that is still alive", async () => {
    const { hostId, file } = await makeHostWithScreenshot("240.51.0.3", new Date());
    // A second, ancient capture on the same, still-current host.
    const oldFile = path.join(path.resolve(config.screenshotDir), `it-old-${Math.random().toString(16).slice(2)}.png`);
    fs.writeFileSync(oldFile, "old");
    await db
      .insertInto("screenshots")
      .values({
        host_id: hostId,
        scan_job_id: scanJobId,
        port: 8080,
        url: "https://240.51.0.3:8080/",
        image_path: oldFile,
        captured_at: new Date(Date.now() - 400 * 86_400_000),
      })
      .execute();

    await runRetentionSweep();

    expect(fs.existsSync(oldFile)).toBe(false);
    // The host itself is current, so its recent capture stays.
    expect(fs.existsSync(file)).toBe(true);
    const remaining = await db.selectFrom("screenshots").select(["id"]).where("host_id", "=", hostId).execute();
    expect(remaining).toHaveLength(1);
  });

  // The case that reclaims everything leaked before any of this existed.
  it("collects files no row points at, once they're past the grace period", async () => {
    await setup();
    const orphan = path.join(path.resolve(config.screenshotDir), `it-orphan-${Math.random().toString(16).slice(2)}.png`);
    fs.writeFileSync(orphan, "orphaned");
    // Backdated past the grace window - a file written seconds ago is
    // indistinguishable from a capture whose row hasn't been inserted yet.
    const old = new Date(Date.now() - 2 * 60 * 60_000);
    fs.utimesSync(orphan, old, old);

    await runRetentionSweep();
    expect(fs.existsSync(orphan)).toBe(false);
  });

  // The grace period is load-bearing: ingest writes the file first and
  // inserts the row immediately after, so a capture landing mid-sweep
  // would otherwise be deleted out from under its own insert.
  it("leaves a freshly written unreferenced file alone", async () => {
    await setup();
    const fresh = path.join(path.resolve(config.screenshotDir), `it-fresh-${Math.random().toString(16).slice(2)}.png`);
    fs.writeFileSync(fresh, "just-written");

    await runRetentionSweep();
    expect(fs.existsSync(fresh)).toBe(true);
    fs.unlinkSync(fresh);
  });

  it("reports storage usage, counting files from disk rather than rows", async () => {
    const { file } = await makeHostWithScreenshot("240.51.0.4");
    const session = await loginAs(admin.username, admin.password);
    const res = await session.get("/api/settings/storage");

    expect(res.status).toBe(200);
    expect(res.body.databaseBytes).toBeGreaterThan(0);
    expect(res.body.screenshots.files).toBeGreaterThanOrEqual(1);
    expect(res.body.screenshots.bytes).toBeGreaterThan(0);
    expect(res.body.tables.map((t: { table: string }) => t.table)).toContain("host_port_observations");
    fs.existsSync(file);
  });

  it("storage is admin-only", async () => {
    const operator = await createTestUser("operator");
    created.push(operator.id);
    const opSession = await loginAs(operator.username, operator.password);
    expect((await opSession.get("/api/settings/storage")).status).toBe(403);
  });
});
