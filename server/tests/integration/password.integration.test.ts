import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, getApp, loginAs, type TestUser } from "./helpers";

// Until these two routes existed, password_hash was only ever written at
// account creation - a shared or leaked credential could only be
// remediated by deleting the account, taking its 2FA enrolment and
// scanner assignments with it. These tests pin the properties that make
// the pair safe rather than just "it changes the hash".
describe("password change and admin reset", () => {
  const created: number[] = [];

  afterAll(async () => {
    for (const id of created) await deleteTestUser(id);
    await closeDb();
  });

  async function user(role: "admin" | "operator" | "user" = "operator"): Promise<TestUser> {
    const u = await createTestUser(role);
    created.push(u.id);
    return u;
  }

  const login = (username: string, password: string) =>
    request(getApp()).post("/auth/login").set("X-Forwarded-Proto", "https").send({ username, password });

  it("changes the password and makes the new one the only one that works", async () => {
    const u = await user();
    const session = await loginAs(u.username, u.password);

    const res = await session
      .post("/auth/password")
      .send({ currentPassword: u.password, newPassword: "Brand-New-Passw0rd" });
    expect(res.status).toBe(204);

    expect((await login(u.username, "Brand-New-Passw0rd")).status).toBe(200);
    expect((await login(u.username, u.password)).status).toBe(401);
  });

  // A live session is not proof the person at the keyboard is the account
  // owner - that's the entire threat this endpoint defends against, so
  // getting it wrong would turn a hijacked session into a takeover.
  it("rejects a wrong current password and leaves the old one working", async () => {
    const u = await user();
    const session = await loginAs(u.username, u.password);

    const res = await session
      .post("/auth/password")
      .send({ currentPassword: "not-the-password", newPassword: "Another-Passw0rd" });
    expect(res.status).toBe(401);

    expect((await login(u.username, u.password)).status).toBe(200);
    expect((await login(u.username, "Another-Passw0rd")).status).toBe(401);
  });

  it("rejects a too-short new password and a no-op change", async () => {
    const u = await user();
    const session = await loginAs(u.username, u.password);

    expect((await session.post("/auth/password").send({ currentPassword: u.password, newPassword: "short" })).status).toBe(400);
    const same = await session.post("/auth/password").send({ currentPassword: u.password, newPassword: u.password });
    expect(same.status).toBe(400);
    expect(same.body.error).toMatch(/differ/);
  });

  it("requires a session", async () => {
    const res = await request(getApp()).post("/auth/password").send({ currentPassword: "x", newPassword: "yyyyyyyy" });
    expect(res.status).toBe(401);
  });

  it("lets an admin reset a forgotten password without knowing the old one", async () => {
    const target = await user();
    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);

    const res = await adminSession.post(`/api/users/${target.id}/password`).send({ password: "Admin-Set-Passw0rd" });
    expect(res.status).toBe(204);

    expect((await login(target.username, "Admin-Set-Passw0rd")).status).toBe(200);
    expect((await login(target.username, target.password)).status).toBe(401);
  });

  // An admin resetting a password must not thereby be able to log in as
  // that user - resetting 2FA is a separate, separately-audited action.
  it("leaves the target's 2FA enrolment untouched", async () => {
    const target = await user();
    await db
      .updateTable("users")
      .set({ totp_enabled: true, totp_secret: "JBSWY3DPEHPK3PXP" })
      .where("id", "=", target.id)
      .execute();

    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);
    expect((await adminSession.post(`/api/users/${target.id}/password`).send({ password: "Reset-Passw0rd" })).status).toBe(204);

    const after = await db
      .selectFrom("users")
      .select(["totp_enabled", "totp_secret"])
      .where("id", "=", target.id)
      .executeTakeFirstOrThrow();
    expect(after.totp_enabled).toBe(true);
    expect(after.totp_secret).toBe("JBSWY3DPEHPK3PXP");

    // And the password really did change, so this isn't passing by doing
    // nothing at all.
    const res = await login(target.username, "Reset-Passw0rd");
    expect(res.status).toBe(200);
    expect(res.body.requiresTotp).toBe(true);
  });

  it("is admin-only, rejects a short password, and 404s an unknown user", async () => {
    const target = await user();
    const operator = await user("operator");
    const opSession = await loginAs(operator.username, operator.password);
    expect((await opSession.post(`/api/users/${target.id}/password`).send({ password: "Whatever-Pass1" })).status).toBe(403);

    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);
    expect((await adminSession.post(`/api/users/${target.id}/password`).send({ password: "tiny" })).status).toBe(400);
    expect((await adminSession.post(`/api/users/999999/password`).send({ password: "Whatever-Pass1" })).status).toBe(404);

    // The rejected attempts must not have changed anything.
    expect((await login(target.username, target.password)).status).toBe(200);
  });

  it("records both actions in the audit log, with the actor and target", async () => {
    const target = await user();
    const admin = await user("admin");
    const adminSession = await loginAs(admin.username, admin.password);
    await adminSession.post(`/api/users/${target.id}/password`).send({ password: "Audited-Passw0rd" });

    const reset = await db
      .selectFrom("audit_log")
      .select(["actor", "details"])
      .where("event", "=", "user.password_reset")
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect(reset.actor).toBe(admin.username);
    expect(reset.details).toMatchObject({ username: target.username });

    const session = await loginAs(target.username, "Audited-Passw0rd");
    await session.post("/auth/password").send({ currentPassword: "Audited-Passw0rd", newPassword: "Self-Chosen-Pw1" });
    const changed = await db
      .selectFrom("audit_log")
      .select(["actor"])
      .where("event", "=", "auth.password_changed")
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect(changed.actor).toBe(target.username);
  });
});
