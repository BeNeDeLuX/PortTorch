import { afterAll, afterEach, describe, expect, it } from "vitest";
import request from "supertest";
import { closeDb, createTestUser, deleteTestUser, getApp, loginAs, type TestUser } from "./helpers";

// GET /api/users is requireAdmin at the router level (users/routes.ts) -
// a representative, easy-to-assert stand-in for the "admin-only, no
// exceptions" tier of routes (scanner agents, schedules, webhooks,
// excludes, user management all follow the same requireAdmin pattern -
// see CLAUDE.md's "Roles and permissions").
describe("RBAC boundaries", () => {
  const createdUsers: TestUser[] = [];

  afterEach(async () => {
    while (createdUsers.length) {
      await deleteTestUser(createdUsers.pop()!.id);
    }
  });

  afterAll(async () => {
    await closeDb();
  });

  it("rejects a request with no session at all", async () => {
    const res = await request(getApp()).get("/api/users");
    expect(res.status).toBe(401);
  });

  it("allows admin to reach an admin-only route", async () => {
    const admin = await createTestUser("admin");
    createdUsers.push(admin);

    const client = await loginAs(admin.username, admin.password);
    const res = await client.get("/api/users");

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("rejects operator from an admin-only route", async () => {
    const operator = await createTestUser("operator");
    createdUsers.push(operator);

    const client = await loginAs(operator.username, operator.password);
    const res = await client.get("/api/users");

    expect(res.status).toBe(403);
  });

  it("rejects a read-only user from an admin-only route", async () => {
    const user = await createTestUser("user");
    createdUsers.push(user);

    const client = await loginAs(user.username, user.password);
    const res = await client.get("/api/users");

    expect(res.status).toBe(403);
  });

  it("rejects a read-only user from an operator-level route (dismissing a scan job)", async () => {
    const user = await createTestUser("user");
    createdUsers.push(user);

    const client = await loginAs(user.username, user.password);
    // Any syntactically valid uuid is enough here - the RBAC check in
    // requireOperator runs before the route looks the id up, so a 403
    // (not 404) is exactly what proves the boundary is enforced first.
    const res = await client.post("/api/scan-jobs/00000000-0000-0000-0000-000000000000/dismiss");

    expect(res.status).toBe(403);
  });
});
