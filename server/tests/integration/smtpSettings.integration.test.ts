import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, getApp, loginAs, type TestUser } from "./helpers";
import request from "supertest";

// SMTP moved out of .env into app_settings so an admin can fix a mail
// server without a redeploy. The properties worth pinning are the ones
// that make storing a live credential in a settings row safe, plus the
// partial-update semantics that keep an unrelated edit from destroying
// working auth.
describe("SMTP settings", () => {
  let admin: TestUser;
  const created: number[] = [];

  beforeEach(async () => {
    admin = await createTestUser("admin");
    created.push(admin.id);
    await db
      .updateTable("app_settings")
      .set({ smtp_host: null, smtp_port: 587, smtp_secure: false, smtp_user: null, smtp_password: null, smtp_from: null })
      .where("id", "=", 1)
      .execute();
  });

  afterAll(async () => {
    for (const id of created) await deleteTestUser(id);
    await db
      .updateTable("app_settings")
      .set({ smtp_host: null, smtp_user: null, smtp_password: null, smtp_from: null })
      .where("id", "=", 1)
      .execute();
    await closeDb();
  });

  const save = async (smtp: unknown) => {
    const session = await loginAs(admin.username, admin.password);
    return session.patch("/api/settings/app").send({ smtp });
  };

  async function storedPassword(): Promise<string | null> {
    const row = await db.selectFrom("app_settings").select(["smtp_password"]).where("id", "=", 1).executeTakeFirstOrThrow();
    return row.smtp_password;
  }

  it("saves settings and reports them back without the password", async () => {
    const res = await save({
      host: "smtp.example.com",
      port: 465,
      secure: true,
      user: "alerts@example.com",
      password: "super-secret",
      from: "porttorch@example.com",
    });
    expect(res.status).toBe(200);
    expect(res.body.smtp).toMatchObject({
      host: "smtp.example.com",
      port: 465,
      secure: true,
      user: "alerts@example.com",
      from: "porttorch@example.com",
      passwordSet: true,
    });

    // The credential itself must never appear in a response body, in any
    // shape - this is the one app_settings value that is a live secret.
    expect(JSON.stringify(res.body)).not.toContain("super-secret");

    const session = await loginAs(admin.username, admin.password);
    const get = await session.get("/api/settings/app");
    expect(JSON.stringify(get.body)).not.toContain("super-secret");
    expect(get.body.smtp.passwordSet).toBe(true);
    expect(get.body.smtp).not.toHaveProperty("password");

    // But it really was stored, so this isn't passing by saving nothing.
    expect(await storedPassword()).toBe("super-secret");
  });

  // The form can't prefill a password it never receives, so a blank field
  // has to mean "keep". Getting this wrong would wipe working credentials
  // every time someone edited the sender address.
  it("keeps the stored password when the field is omitted", async () => {
    await save({ host: "smtp.example.com", port: 587, secure: false, user: "u", password: "keep-me", from: null });
    const res = await save({ host: "smtp.example.com", port: 2525, secure: false, user: "u", from: "new@example.com" });

    expect(res.status).toBe(200);
    expect(res.body.smtp.port).toBe(2525);
    expect(res.body.smtp.from).toBe("new@example.com");
    expect(res.body.smtp.passwordSet).toBe(true);
    expect(await storedPassword()).toBe("keep-me");
  });

  it("clears the password when explicitly sent as null", async () => {
    await save({ host: "smtp.example.com", port: 587, secure: false, user: "u", password: "drop-me", from: null });
    const res = await save({ host: "smtp.example.com", port: 587, secure: false, user: null, password: null, from: null });

    expect(res.body.smtp.passwordSet).toBe(false);
    expect(await storedPassword()).toBeNull();
  });

  it("rejects an invalid port and leaves the stored settings untouched", async () => {
    await save({ host: "smtp.example.com", port: 587, secure: false, user: null, from: null });
    const res = await save({ host: "smtp.example.com", port: 99999, secure: false, user: null, from: null });
    expect(res.status).toBe(400);

    const row = await db.selectFrom("app_settings").select(["smtp_port"]).where("id", "=", 1).executeTakeFirstOrThrow();
    expect(row.smtp_port).toBe(587);
  });

  it("is admin-only", async () => {
    const operator = await createTestUser("operator");
    created.push(operator.id);
    const opSession = await loginAs(operator.username, operator.password);
    expect((await opSession.get("/api/settings/app")).status).toBe(403);
    expect(
      (await opSession.patch("/api/settings/app").send({ smtp: { host: "x", port: 25, secure: false, user: null, from: null } }))
        .status
    ).toBe(403);
  });

  it("saving SMTP leaves the other app settings alone", async () => {
    const session = await loginAs(admin.username, admin.password);
    await session.patch("/api/settings/app").send({ hostRetentionDays: 42 });
    await save({ host: "smtp.example.com", port: 587, secure: false, user: null, from: null });

    const after = await session.get("/api/settings/app");
    expect(after.body.hostRetentionDays).toBe(42);
  });

  // The test endpoint has to fail loudly rather than pretend, and must
  // not 5xx - a delivery failure is the answer the admin asked for.
  it("refuses a test send when no host is configured", async () => {
    const session = await loginAs(admin.username, admin.password);
    const res = await session.post("/api/settings/smtp/test").send({ to: "someone@example.com" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/no mail server/i);
  });

  it("reports a failed test as ok:false rather than an error status", async () => {
    // Port 1 on loopback: nothing listens, so the send genuinely fails.
    await save({ host: "127.0.0.1", port: 1, secure: false, user: null, from: "porttorch@example.com" });
    const session = await loginAs(admin.username, admin.password);
    const res = await session.post("/api/settings/smtp/test").send({ to: "someone@example.com" });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toBeTruthy();
  }, 20000);

  it("rejects a test send to a malformed address", async () => {
    const session = await loginAs(admin.username, admin.password);
    const res = await session.post("/api/settings/smtp/test").send({ to: "not-an-address" });
    expect(res.status).toBe(400);
  });
});
