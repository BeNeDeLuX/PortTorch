import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { closeDb, createTestUser, deleteTestUser, loginAs, type SessionClient, type TestUser } from "./helpers";

// Same pattern as staleScan.integration.test.ts's "settings - stale scan
// threshold" describe block - confirms the setting is live-editable via
// PATCH /api/settings/app (admin-only), and separately that the actual
// read path Fleet Health/the Dashboard use (GET /api/scan-jobs/queue-
// threshold) is reachable by every role, not just admins - unlike
// PATCH/GET /api/settings/app itself, since Fleet Health's Scan Queue
// card needs to compute the same status for whoever's looking at it.
describe("settings - scan queue warning threshold", () => {
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let operatorClient: SessionClient;
  let originalValue: number;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    operatorClient = await loginAs(operator.username, operator.password);
    const current = await adminClient.get("/api/settings/app");
    originalValue = current.body.scanQueueWarningThreshold;
  });

  afterAll(async () => {
    await adminClient.patch("/api/settings/app").send({ scanQueueWarningThreshold: originalValue });
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("is live-editable by an admin and reflected on the next read", async () => {
    const patchRes = await adminClient.patch("/api/settings/app").send({ scanQueueWarningThreshold: 5 });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body.scanQueueWarningThreshold).toBe(5);

    const getRes = await adminClient.get("/api/settings/app");
    expect(getRes.body.scanQueueWarningThreshold).toBe(5);
  });

  it("rejects a non-positive value", async () => {
    const res = await adminClient.patch("/api/settings/app").send({ scanQueueWarningThreshold: 0 });
    expect(res.status).toBe(400);
  });

  it("rejects a non-admin trying to change it", async () => {
    const res = await operatorClient.patch("/api/settings/app").send({ scanQueueWarningThreshold: 3 });
    expect(res.status).toBe(403);
  });

  it("GET /api/scan-jobs/queue-threshold reflects the current value and is reachable by a non-admin", async () => {
    await adminClient.patch("/api/settings/app").send({ scanQueueWarningThreshold: 7 });

    const asOperator = await operatorClient.get("/api/scan-jobs/queue-threshold");
    expect(asOperator.status).toBe(200);
    expect(asOperator.body).toEqual({ warningThreshold: 7 });

    const asAdmin = await adminClient.get("/api/scan-jobs/queue-threshold");
    expect(asAdmin.status).toBe(200);
    expect(asAdmin.body).toEqual({ warningThreshold: 7 });
  });
});
