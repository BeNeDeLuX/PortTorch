import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, getApp, loginAs, type SessionClient, type TestUser } from "./helpers";

describe("Webhooks (webhook + email channels)", () => {
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;
  const createdIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
  });

  afterEach(async () => {
    if (createdIds.length > 0) {
      await db.deleteFrom("webhooks").where("id", "in", createdIds).execute();
      createdIds.length = 0;
    }
  });

  afterAll(async () => {
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("requires admin to create a channel", async () => {
    const res = await operatorClient
      .post("/api/webhooks")
      .send({ name: "not-allowed", channelType: "webhook", url: "https://example.test/hook", events: ["host.new"] });
    expect(res.status).toBe(403);
  });

  it("creates a webhook channel and defaults channelType when omitted (backward compatible with the pre-email create shape)", async () => {
    const res = await adminClient.post("/api/webhooks").send({ name: "it-legacy-webhook", url: "https://example.test/hook", events: ["host.new"] });
    expect(res.status).toBe(201);
    expect(res.body.channel_type).toBe("webhook");
    expect(res.body.url).toBe("https://example.test/hook");
    expect(res.body.email_to).toBeNull();
    createdIds.push(res.body.id);
  });

  it("creates an email channel with a comma-joined recipient list", async () => {
    const res = await adminClient
      .post("/api/webhooks")
      .send({ name: "it-email-channel", channelType: "email", emailTo: "a@example.test, b@example.test", events: ["certificate.expiring_soon"] });
    expect(res.status).toBe(201);
    expect(res.body.channel_type).toBe("email");
    expect(res.body.email_to).toBe("a@example.test, b@example.test");
    expect(res.body.url).toBeNull();
    createdIds.push(res.body.id);
  });

  it("rejects an email channel with no emailTo", async () => {
    const res = await adminClient.post("/api/webhooks").send({ name: "it-bad-email", channelType: "email", events: ["host.new"] });
    expect(res.status).toBe(400);
  });

  it("rejects an email channel with an invalid address in the list", async () => {
    const res = await adminClient
      .post("/api/webhooks")
      .send({ name: "it-bad-email-2", channelType: "email", emailTo: "ok@example.test, not-an-email", events: ["host.new"] });
    expect(res.status).toBe(400);
  });

  it("rejects a webhook channel with no url", async () => {
    const res = await adminClient.post("/api/webhooks").send({ name: "it-bad-webhook", channelType: "webhook", events: ["host.new"] });
    expect(res.status).toBe(400);
  });

  it("lists both channel types with their type-specific target field populated", async () => {
    const created = await adminClient
      .post("/api/webhooks")
      .send({ name: "it-list-email", channelType: "email", emailTo: "list-test@example.test", events: ["host.new"] });
    createdIds.push(created.body.id);

    const res = await adminClient.get("/api/webhooks");
    expect(res.status).toBe(200);
    const row = (res.body as Array<{ id: string; channel_type: string; email_to: string | null }>).find((w) => w.id === created.body.id);
    expect(row?.channel_type).toBe("email");
    expect(row?.email_to).toBe("list-test@example.test");
  });

  it("an email channel's /test endpoint reports failure when SMTP isn't configured, rather than throwing", async () => {
    const created = await adminClient
      .post("/api/webhooks")
      .send({ name: "it-test-email", channelType: "email", emailTo: "test-endpoint@example.test", events: ["host.new"] });
    createdIds.push(created.body.id);

    const res = await adminClient.post(`/api/webhooks/${created.body.id}/test`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toMatch(/SMTP is not configured/i);
  });

  it("requires authentication to list webhooks", async () => {
    const res = await request(getApp()).get("/api/webhooks");
    expect(res.status).toBe(401);
  });
});
