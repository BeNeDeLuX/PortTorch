import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, loginAs, type SessionClient, type TestUser } from "./helpers";

// audit_log used to be kept forever with no pruning at all - it's now
// purged by the same runRetentionSweep() the hourly ticker and the
// Settings page's "Clean up now" button already share for hosts, tied to
// the same admin-editable app_settings.host_retention_days window rather
// than a second, separate setting.
describe("retention also purges audit_log entries older than host_retention_days", () => {
  let admin: TestUser;
  let client: SessionClient;
  let originalRetentionDays: number;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    const current = await client.get("/api/settings/app");
    originalRetentionDays = current.body.hostRetentionDays;
  });

  afterAll(async () => {
    await client.patch("/api/settings/app").send({ hostRetentionDays: originalRetentionDays });
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function insertAuditEntry(event: string, ageDays: number): Promise<void> {
    const createdAt = new Date(Date.now() - ageDays * 24 * 60 * 60_000).toISOString();
    await db
      .insertInto("audit_log")
      .values({ event, actor: "it-audit-retention", source_ip: null, details: JSON.stringify({}), created_at: createdAt })
      .execute();
  }

  it("purges entries older than the retention window, keeps recent ones", async () => {
    await client.patch("/api/settings/app").send({ hostRetentionDays: 7 });
    await insertAuditEntry("it.old_entry", 10);
    await insertAuditEntry("it.recent_entry", 1);

    const res = await client.post("/api/settings/retention/run-now");
    expect(res.status).toBe(200);
    expect(res.body.purgedAuditLogEntries).toBeGreaterThanOrEqual(1);

    const old = await db.selectFrom("audit_log").select(["id"]).where("event", "=", "it.old_entry").executeTakeFirst();
    const recent = await db
      .selectFrom("audit_log")
      .select(["id"])
      .where("event", "=", "it.recent_entry")
      .executeTakeFirst();
    expect(old).toBeUndefined();
    expect(recent).toBeDefined();

    await db.deleteFrom("audit_log").where("event", "=", "it.recent_entry").execute();
  });

  it("a retention window of 0 disables the audit log purge too, same as the host sweep", async () => {
    await client.patch("/api/settings/app").send({ hostRetentionDays: 0 });
    await insertAuditEntry("it.should_survive", 3650);

    const res = await client.post("/api/settings/retention/run-now");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ purgedHosts: 0, purgedAuditLogEntries: 0 });

    const survived = await db
      .selectFrom("audit_log")
      .select(["id"])
      .where("event", "=", "it.should_survive")
      .executeTakeFirst();
    expect(survived).toBeDefined();

    await db.deleteFrom("audit_log").where("event", "=", "it.should_survive").execute();
  });
});
