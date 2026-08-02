import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  loginAs,
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

describe("account preferences", () => {
  let user: TestUser;
  let client: SessionClient;
  let agent: TestAgent;

  beforeAll(async () => {
    user = await createTestUser("user");
    client = await loginAs(user.username, user.password);
    agent = await createTestAgent("it-prefs-agent");
  });

  afterAll(async () => {
    await deleteTestUser(user.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  afterEach(async () => {
    // Reset between tests within this file so each starts from a known
    // state, without needing a fresh user per test.
    await client.patch("/auth/preferences").send({
      theme: null,
      hostsPageSize: null,
      showActiveScansBanner: true,
      defaultScannerAgentId: null,
      timezone: null,
      timeFormat: null,
      accentColor: null,
    });
  });

  it("defaults to no overrides for a brand-new account", async () => {
    const res = await client.get("/auth/me");
    expect(res.status).toBe(200);
    expect(res.body.preferences).toEqual({
      theme: null,
      hostsPageSize: null,
      showActiveScansBanner: true,
      defaultScannerAgentId: null,
      timezone: null,
      timeFormat: null,
      accentColor: null,
    });
  });

  it("persists a partial update and leaves other fields untouched", async () => {
    const first = await client.patch("/auth/preferences").send({ theme: "light" });
    expect(first.status).toBe(200);
    expect(first.body.theme).toBe("light");
    expect(first.body.hostsPageSize).toBeNull();

    const second = await client.patch("/auth/preferences").send({ hostsPageSize: 100 });
    expect(second.status).toBe(200);
    expect(second.body.theme).toBe("light");
    expect(second.body.hostsPageSize).toBe(100);

    const me = await client.get("/auth/me");
    expect(me.body.preferences).toEqual({
      theme: "light",
      hostsPageSize: 100,
      showActiveScansBanner: true,
      defaultScannerAgentId: null,
      timezone: null,
      timeFormat: null,
      accentColor: null,
    });
  });

  it("clears a field back to null with an explicit null, distinct from omitting it", async () => {
    await client.patch("/auth/preferences").send({ theme: "dark" });
    const cleared = await client.patch("/auth/preferences").send({ theme: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body.theme).toBeNull();
  });

  it("accepts a real scanner agent id for the default scanner", async () => {
    const res = await client.patch("/auth/preferences").send({ defaultScannerAgentId: agent.id });
    expect(res.status).toBe(200);
    expect(res.body.defaultScannerAgentId).toBe(agent.id);
  });

  it("rejects a default scanner id that doesn't exist", async () => {
    const res = await client
      .patch("/auth/preferences")
      .send({ defaultScannerAgentId: "00000000-0000-0000-0000-000000000000" });
    expect(res.status).toBe(400);
  });

  it("rejects an out-of-range page size", async () => {
    const res = await client.patch("/auth/preferences").send({ hostsPageSize: 500 });
    expect(res.status).toBe(400);
  });

  it("accepts a real IANA timezone and a time format", async () => {
    const res = await client.patch("/auth/preferences").send({ timezone: "Europe/Berlin", timeFormat: "h24" });
    expect(res.status).toBe(200);
    expect(res.body.timezone).toBe("Europe/Berlin");
    expect(res.body.timeFormat).toBe("h24");
  });

  it("rejects an unknown timezone", async () => {
    const res = await client.patch("/auth/preferences").send({ timezone: "Not/A_Real_Zone" });
    expect(res.status).toBe(400);
  });

  // Regression check: Intl.supportedValuesOf("timeZone") - what
  // VALID_TIMEZONES in auth/routes.ts is built from - only enumerates
  // canonical IANA identifiers and does NOT include "UTC" itself (caught
  // by testing the real dropdown, not assumed), even though
  // Intl.DateTimeFormat accepts "UTC" as a timeZone value just fine. "UTC"
  // is explicitly added to VALID_TIMEZONES for exactly this reason.
  it("accepts the explicit 'UTC' timezone", async () => {
    const res = await client.patch("/auth/preferences").send({ timezone: "UTC" });
    expect(res.status).toBe(200);
    expect(res.body.timezone).toBe("UTC");
  });

  it("rejects a time format outside h12/h24", async () => {
    const res = await client.patch("/auth/preferences").send({ timeFormat: "24h" });
    expect(res.status).toBe(400);
  });

  it("clears timezone/timeFormat back to null with an explicit null", async () => {
    await client.patch("/auth/preferences").send({ timezone: "America/New_York", timeFormat: "h12" });
    const cleared = await client.patch("/auth/preferences").send({ timezone: null, timeFormat: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body.timezone).toBeNull();
    expect(cleared.body.timeFormat).toBeNull();
  });

  it("accepts the orange accent color", async () => {
    const res = await client.patch("/auth/preferences").send({ accentColor: "orange" });
    expect(res.status).toBe(200);
    expect(res.body.accentColor).toBe("orange");
  });

  it("accepts the blue accent color", async () => {
    const res = await client.patch("/auth/preferences").send({ accentColor: "blue" });
    expect(res.status).toBe(200);
    expect(res.body.accentColor).toBe("blue");
  });

  it("rejects an accent color outside green/orange/blue", async () => {
    const res = await client.patch("/auth/preferences").send({ accentColor: "purple" });
    expect(res.status).toBe(400);
  });

  it("clears accentColor back to null with an explicit null", async () => {
    await client.patch("/auth/preferences").send({ accentColor: "orange" });
    const cleared = await client.patch("/auth/preferences").send({ accentColor: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body.accentColor).toBeNull();
  });
});
