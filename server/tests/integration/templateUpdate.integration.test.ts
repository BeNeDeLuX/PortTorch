import { afterAll, beforeEach, describe, expect, it } from "vitest";
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
  type TestAgent,
  type TestUser,
} from "./helpers";

// The admin-triggered nuclei template refresh - structurally the binary
// self-update's twin, but with one deliberate divergence in how its state
// is carried (requested_at survives a give-up, so the status column is
// what "is one outstanding" keys on). That divergence is what most of
// this file actually pins down, since it's the part that can't be checked
// by reading the self-update tests.
describe("nuclei template update requests", () => {
  let agent: TestAgent;
  let admin: TestUser;

  beforeEach(async () => {
    agent = await createTestAgent("it-tplupd-agent");
    admin = await createTestUser("admin");
  });

  afterAll(async () => {
    await closeDb();
  });

  async function cleanup() {
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
  }

  const poll = () =>
    request(getApp()).get("/api/ingest/template-update-requested").set("Authorization", `Bearer ${agent.apiKey}`);
  const report = (body: unknown) =>
    request(getApp())
      .patch("/api/ingest/template-update-outcome")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send(body);

  async function agentRow() {
    return db
      .selectFrom("scanner_agents")
      .select([
        "template_update_requested_at",
        "template_update_status",
        "template_update_failure_reason",
        "template_update_attempt_count",
      ])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
  }

  it("is invisible to the scanner until an admin actually requests it", async () => {
    expect((await poll()).body).toEqual({ requested: false });
    await cleanup();
  });

  it("becomes visible on the scanner's next poll once requested, and clears on success", async () => {
    const session = await loginAs(admin.username, admin.password);
    const res = await session.post(`/api/agents/${agent.id}/request-template-update`);
    expect(res.status).toBe(204);

    expect((await poll()).body).toEqual({ requested: true });
    expect((await agentRow()).template_update_status).toBe("pending");

    expect((await report({ status: "succeeded" })).status).toBe(204);

    const after = await agentRow();
    expect(after.template_update_status).toBeNull();
    expect(after.template_update_requested_at).toBeNull();
    expect(after.template_update_attempt_count).toBe(0);
    expect((await poll()).body).toEqual({ requested: false });
    await cleanup();
  });

  it("keeps retrying until the attempt cap, then stops polling but keeps the reason visible", async () => {
    const session = await loginAs(admin.username, admin.password);
    await session.post(`/api/agents/${agent.id}/request-template-update`);

    // Two failures: still pending, so the scanner keeps picking it up.
    await report({ status: "failed", reason: "nuclei: command not found" });
    await report({ status: "failed", reason: "nuclei: command not found" });
    expect((await agentRow()).template_update_status).toBe("pending");
    expect((await poll()).body).toEqual({ requested: true });

    // Third exhausts the cap - terminal.
    await report({ status: "failed", reason: "nuclei: command not found" });
    const after = await agentRow();
    expect(after.template_update_status).toBe("failed");
    expect(after.template_update_failure_reason).toBe("nuclei: command not found");
    expect(after.template_update_attempt_count).toBe(3);

    // The scanner must stop asking, but the request timestamp is
    // deliberately kept (it's the anchor the opportunistic clear below
    // compares a reported template age against).
    expect((await poll()).body).toEqual({ requested: false });
    expect(after.template_update_requested_at).not.toBeNull();
    await cleanup();
  });

  it("can be re-triggered after a give-up, but not while one is still pending", async () => {
    const session = await loginAs(admin.username, admin.password);
    await session.post(`/api/agents/${agent.id}/request-template-update`);

    // Still pending - a second request would silently reset the attempt
    // counter and mask an in-flight retry cycle.
    expect((await session.post(`/api/agents/${agent.id}/request-template-update`)).status).toBe(409);

    for (let i = 0; i < 3; i++) await report({ status: "failed", reason: "boom" });
    expect((await agentRow()).template_update_status).toBe("failed");

    // Given up - an admin who fixed the cause must be able to ask again.
    expect((await session.post(`/api/agents/${agent.id}/request-template-update`)).status).toBe(204);
    const after = await agentRow();
    expect(after.template_update_status).toBe("pending");
    expect(after.template_update_attempt_count).toBe(0);
    expect(after.template_update_failure_reason).toBeNull();
    await cleanup();
  });

  // The whole point of keeping requested_at past a give-up: an admin who
  // fixed it by hand on the host (rather than re-triggering here) would
  // otherwise be stuck with an undismissable "template update failed".
  it("clears a given-up request once the scanner reports a tree newer than the request", async () => {
    const session = await loginAs(admin.username, admin.password);
    await session.post(`/api/agents/${agent.id}/request-template-update`);
    for (let i = 0; i < 3; i++) await report({ status: "failed", reason: "permission denied" });
    expect((await agentRow()).template_update_status).toBe("failed");

    // Backdate the request so both timestamps below can be genuinely in
    // the past - the header parser rejects a future one outright (a clock
    // problem would otherwise read as permanently fresh), so a test that
    // reported "now + 1s" would only be passing on its 60s skew
    // tolerance rather than on the comparison actually under test.
    const requestedAt = new Date(Date.now() - 3600_000);
    await db
      .updateTable("scanner_agents")
      .set({ template_update_requested_at: requestedAt })
      .where("id", "=", agent.id)
      .execute();

    // A tree older than the request is not evidence of anything.
    await request(getApp())
      .get("/api/ingest/template-update-requested")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .set("X-Scanner-Nuclei-Templates-Updated", new Date(requestedAt.getTime() - 86_400_000).toISOString());
    expect((await agentRow()).template_update_status).toBe("failed");

    // A tree written after the request was made is.
    await request(getApp())
      .get("/api/ingest/template-update-requested")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .set("X-Scanner-Nuclei-Templates-Updated", new Date(requestedAt.getTime() + 60_000).toISOString());

    const after = await agentRow();
    expect(after.template_update_status).toBeNull();
    expect(after.template_update_requested_at).toBeNull();
    expect(after.template_update_failure_reason).toBeNull();
    expect(after.template_update_attempt_count).toBe(0);
    await cleanup();
  });

  it("is admin-only, and rejects an unknown agent id", async () => {
    const operator = await createTestUser("operator");
    const opSession = await loginAs(operator.username, operator.password);
    expect((await opSession.post(`/api/agents/${agent.id}/request-template-update`)).status).toBe(403);
    await deleteTestUser(operator.id);

    const session = await loginAs(admin.username, admin.password);
    const res = await session.post(`/api/agents/00000000-0000-0000-0000-000000000000/request-template-update`);
    expect(res.status).toBe(409);
    await cleanup();
  });

  it("requires scanner auth on both ingest endpoints", async () => {
    expect((await request(getApp()).get("/api/ingest/template-update-requested")).status).toBe(401);
    expect(
      (await request(getApp()).patch("/api/ingest/template-update-outcome").send({ status: "succeeded" })).status
    ).toBe(401);
    await cleanup();
  });
});
