import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

// The scanner piggybacks template age on every ingest request, the same
// way it already reports version and submit-queue depth - so this is
// really testing that the header survives the whole path from request to
// what the Scanner Agents / Fleet Health pages read.
describe("nuclei template age reporting", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-templates-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function ping(headers: Record<string, string> = {}) {
    return request(getApp())
      .get("/api/ingest/excludes")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .set(headers);
  }

  it("is null before any scanner reports one", async () => {
    const row = await db
      .selectFrom("scanner_agents")
      .select(["nuclei_templates_updated_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_templates_updated_at).toBeNull();
  });

  it("records the reported timestamp and surfaces it on GET /api/agents", async () => {
    const reported = "2026-05-01T08:30:00Z";
    expect((await ping({ "X-Scanner-Nuclei-Templates-Updated": reported })).status).toBe(200);

    const row = await db
      .selectFrom("scanner_agents")
      .select(["nuclei_templates_updated_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_templates_updated_at?.toISOString()).toBe("2026-05-01T08:30:00.000Z");

    const list = await client.get("/api/agents");
    const listed = list.body.find((a: { id: string }) => a.id === agent.id);
    expect(new Date(listed.nuclei_templates_updated_at).toISOString()).toBe("2026-05-01T08:30:00.000Z");
  });

  it("moves forward when the scanner refreshes its templates", async () => {
    await ping({ "X-Scanner-Nuclei-Templates-Updated": "2026-06-10T00:00:00Z" });
    const row = await db
      .selectFrom("scanner_agents")
      .select(["nuclei_templates_updated_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_templates_updated_at?.toISOString()).toBe("2026-06-10T00:00:00.000Z");
  });

  it("is NOT cleared by a scanner build that doesn't send the header", async () => {
    // Unlike version/submit_queue_pending, absence here means "this build
    // can't tell us", not "there are no templates" - wiping a known value
    // would make a downgraded or mixed-version fleet look unknown.
    expect((await ping()).status).toBe(200);

    const row = await db
      .selectFrom("scanner_agents")
      .select(["nuclei_templates_updated_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_templates_updated_at?.toISOString()).toBe("2026-06-10T00:00:00.000Z");
  });

  it("ignores a garbage or future value rather than storing it", async () => {
    await ping({ "X-Scanner-Nuclei-Templates-Updated": "not-a-date" });
    await ping({ "X-Scanner-Nuclei-Templates-Updated": "2099-01-01T00:00:00Z" });

    const row = await db
      .selectFrom("scanner_agents")
      .select(["nuclei_templates_updated_at"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_templates_updated_at?.toISOString()).toBe("2026-06-10T00:00:00.000Z");
  });
});
