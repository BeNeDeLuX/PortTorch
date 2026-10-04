import { sql } from "kysely";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runScannerAutoUpdate } from "../../src/scannerUpdate/autoUpdate";
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

// Auto-update only ever sets the flag an admin's Update click sets; the
// scanner's own watcher applies it. What is pinned here is who gets it.
describe("scanner auto-update", () => {
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;
  const agents: TestAgent[] = [];
  let previousRelease: string | null = null;
  let previousSetting = false;

  async function agent(prefix: string, values: Record<string, unknown>): Promise<TestAgent> {
    const a = await createTestAgent(prefix);
    agents.push(a);
    await db
      .updateTable("scanner_agents")
      .set({ version: "0.20.0", last_seen_at: new Date(), ...values })
      .where("id", "=", a.id)
      .execute();
    return a;
  }

  async function requestedIds(): Promise<string[]> {
    const ids = agents.map((a) => a.id);
    return (await runScannerAutoUpdate()).map((r) => r.scannerAgentId).filter((id) => ids.includes(id));
  }

  async function resetUpdateState() {
    await db
      .updateTable("scanner_agents")
      .set({ update_requested_at: null, update_request_status: null, update_attempt_count: 0 })
      .where("id", "in", agents.map((a) => a.id))
      .execute();
  }

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
    const release = await db.selectFrom("scanner_release_cache").select("latest_version").where("id", "=", 1).executeTakeFirstOrThrow();
    previousRelease = release.latest_version;
    await db.updateTable("scanner_release_cache").set({ latest_version: "0.30.0" }).where("id", "=", 1).execute();
    const settings = await db.selectFrom("app_settings").select("scanner_auto_update").where("id", "=", 1).executeTakeFirstOrThrow();
    previousSetting = settings.scanner_auto_update;
  });

  afterAll(async () => {
    await db.updateTable("scanner_release_cache").set({ latest_version: previousRelease }).where("id", "=", 1).execute();
    await db.updateTable("app_settings").set({ scanner_auto_update: previousSetting }).where("id", "=", 1).execute();
    for (const a of agents) await deleteTestAgent(a.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("does nothing while the fleet default is off and no scanner opted in", async () => {
    await db.updateTable("app_settings").set({ scanner_auto_update: false }).where("id", "=", 1).execute();
    const behind = await agent("it-auto-default", {});
    expect(await requestedIds()).toEqual([]);
    const row = await db.selectFrom("scanner_agents").select("update_request_status").where("id", "=", behind.id).executeTakeFirstOrThrow();
    expect(row.update_request_status).toBeNull();
  });

  it("follows the fleet default, and a per-scanner pin overrides it either way", async () => {
    const follows = agents[0];
    const optedIn = await agent("it-auto-on", { auto_update: true });
    const optedOut = await agent("it-auto-off", { auto_update: false });

    // Default off: only the scanner pinned on.
    expect(await requestedIds()).toEqual([optedIn.id]);
    await resetUpdateState();

    // Default on: everyone except the scanner pinned off.
    expect((await adminClient.patch("/api/settings/app").send({ scannerAutoUpdate: true })).status).toBe(200);
    expect((await requestedIds()).sort()).toEqual([follows.id, optedIn.id].sort());
    const off = await db.selectFrom("scanner_agents").select("update_request_status").where("id", "=", optedOut.id).executeTakeFirstOrThrow();
    expect(off.update_request_status).toBeNull();

    const audit = await db
      .selectFrom("audit_log")
      .select(["actor"])
      .where("event", "=", "agent.update_requested")
      .where(sql<string>`details->>'scanner_agent_id'`, "=", follows.id)
      .execute();
    expect(audit.map((a) => a.actor)).toContain("auto-update");
    await resetUpdateState();
  });

  it("leaves current, offline, revoked and failed scanners alone", async () => {
    const current = await agent("it-auto-current", { version: "0.30.0" });
    const ahead = await agent("it-auto-ahead", { version: "0.31.0" });
    const offline = await agent("it-auto-offline", { last_seen_at: new Date(Date.now() - 60 * 60 * 1000) });
    const revoked = await agent("it-auto-revoked", { revoked_at: new Date() });
    // Terminal after three attempts: an admin has to look at it, and a
    // re-request every five minutes would turn that into a retry loop.
    const failed = await agent("it-auto-failed", { update_request_status: "failed", update_failure_reason: "not writable" });

    const requested = await requestedIds();
    for (const a of [current, ahead, offline, revoked, failed]) expect(requested).not.toContain(a.id);
    await resetUpdateState();
    await db.updateTable("scanner_agents").set({ revoked_at: null }).where("id", "=", revoked.id).execute();
  });

  it("does not request twice while one is outstanding", async () => {
    const first = await requestedIds();
    expect(first.length).toBeGreaterThan(0);
    expect(await requestedIds()).toEqual([]);
    await resetUpdateState();
  });

  it("lets an admin pin a scanner, and only an admin", async () => {
    const a = agents[0];
    expect((await operatorClient.put(`/api/agents/${a.id}/auto-update`).send({ autoUpdate: false })).status).toBe(403);
    expect((await adminClient.put(`/api/agents/${a.id}/auto-update`).send({ autoUpdate: false })).status).toBe(204);
    let row = await db.selectFrom("scanner_agents").select("auto_update").where("id", "=", a.id).executeTakeFirstOrThrow();
    expect(row.auto_update).toBe(false);
    expect((await adminClient.put(`/api/agents/${a.id}/auto-update`).send({ autoUpdate: null })).status).toBe(204);
    row = await db.selectFrom("scanner_agents").select("auto_update").where("id", "=", a.id).executeTakeFirstOrThrow();
    expect(row.auto_update).toBeNull();
    expect((await adminClient.put(`/api/agents/${a.id}/auto-update`).send({ autoUpdate: "yes" })).status).toBe(400);

    const listed = await adminClient.get("/api/agents");
    expect(listed.body.find((x: { id: string }) => x.id === a.id)).toHaveProperty("auto_update", null);
    const settings = await adminClient.get("/api/settings/app");
    expect(settings.body.scannerAutoUpdate).toBe(true);
  });

  // Last, because a marked canary gates every other scanner in the
  // database until it is cleared again.
  it("staggers: canaries first, the rest once a canary scanned on the release", async () => {
    const canary = await agent("it-auto-canary", { update_canary: true, auto_update: true });
    const rest = await agent("it-auto-rest", { auto_update: true });
    const report = (a: TestAgent, version: string) =>
      request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${a.apiKey}`).set("X-Scanner-Version", version);
    const changedAt = async (a: TestAgent) =>
      (await db.selectFrom("scanner_agents").select("version_changed_at").where("id", "=", a.id).executeTakeFirstOrThrow())
        .version_changed_at;

    // The canary is behind too: only it is asked.
    let requested = await requestedIds();
    expect(requested).toContain(canary.id);
    expect(requested).not.toContain(rest.id);
    await resetUpdateState();

    // On the release, but nothing scanned on it yet: still waiting.
    await report(canary, "0.30.0");
    const firstChange = await changedAt(canary);
    expect(firstChange).not.toBeNull();
    expect(await requestedIds()).not.toContain(rest.id);
    let status = await adminClient.get("/api/agents/auto-update-status");
    expect(status.body.gate).toBe("waiting");
    expect(status.body.canaries.find((c: { id: string }) => c.id === canary.id)).toMatchObject({ onLatest: true, provenOnLatest: false });

    // Reporting the same version again does not move the marker.
    await report(canary, "0.30.0");
    expect(await changedAt(canary)).toEqual(firstChange);

    // A completed scan on the new release opens the gate.
    // Every request a real scanner makes carries its version; one without
    // the header records the version as unknown.
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${canary.apiKey}`)
      .set("X-Scanner-Version", "0.30.0")
      .send({ targetSpec: "10.0.0.1", portSpec: "22" });
    await request(getApp())
      .patch(`/api/ingest/scan-jobs/${job.body.id}`)
      .set("Authorization", `Bearer ${canary.apiKey}`)
      .set("X-Scanner-Version", "0.30.0")
      .send({ status: "completed" });
    expect(await changedAt(canary)).toEqual(firstChange);
    status = await adminClient.get("/api/agents/auto-update-status");
    expect(status.body.gate).toBe("open");
    expect(await requestedIds()).toContain(rest.id);

    // A restricted session sees the gate but not other scanners' names.
    const restrictedStatus = await operatorClient.get("/api/agents/auto-update-status");
    expect(restrictedStatus.body.gate).toBe("open");

    expect((await adminClient.put(`/api/agents/${canary.id}/auto-update`).send({ canary: false })).status).toBe(204);
    expect((await adminClient.put(`/api/agents/${canary.id}/auto-update`).send({})).status).toBe(400);
    status = await adminClient.get("/api/agents/auto-update-status");
    expect(status.body.gate).toBe("none");
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", canary.id).execute();
    await resetUpdateState();
  });
});
