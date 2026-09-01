import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { SCANNER_TUNABLES } from "../../src/scannerConfig/tunables";
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

// The Configure dialog could only ever show the shipped default beside
// each field, because the webserver cannot read a file on the scanner's
// host - so an operator who had tuned that file saw a number that did not
// apply to their scanner, in the one field where it matters (blank means
// "use whatever the file says"). The scanner now reports it.
describe("scanner base config reporting", () => {
  let agent: TestAgent;
  let admin: TestUser;

  beforeAll(async () => {
    agent = await createTestAgent("it-baseconfig-agent");
    admin = await createTestUser("admin");
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  function report(body: unknown) {
    return request(getApp())
      .put("/api/ingest/config-report")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send(body as object);
  }

  async function stored(): Promise<Record<string, number> | null> {
    const row = await db
      .selectFrom("scanner_agents")
      .select(["base_config"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
    return row.base_config;
  }

  it("starts out unknown rather than assuming the shipped defaults", async () => {
    // null and "the defaults" have to stay distinguishable, or the dialog
    // cannot honestly label what it is showing.
    expect(await stored()).toBeNull();
  });

  it("stores what the scanner reports", async () => {
    const res = await report({ masscanRate: 250, concurrency: 12, maxConcurrentScans: 3 });
    expect(res.status).toBe(204);
    expect(await stored()).toEqual({ masscanRate: 250, concurrency: 12, maxConcurrentScans: 3 });
  });

  it("drops keys it doesn't know instead of rejecting the whole report", async () => {
    // A scanner of a different vintage may report a field this webserver
    // doesn't expose. Refusing over it would lose the good values too -
    // the opposite of the admin-facing save, where an unknown key is a
    // typo that must not look like it worked.
    const res = await report({ masscanRate: 300, somethingNewer: 42 });
    expect(res.status).toBe(204);
    expect(await stored()).toEqual({ masscanRate: 300 });
  });

  it("drops a value outside the setting's own bounds", async () => {
    // Displayed as "your config.yaml says this", so an impossible number
    // would be misinformation rather than a harmless oddity.
    const concurrency = SCANNER_TUNABLES.find((t) => t.key === "concurrency")!;
    const res = await report({ masscanRate: 400, concurrency: concurrency.max + 1 });
    expect(res.status).toBe(204);
    expect(await stored()).toEqual({ masscanRate: 400 });
  });

  it("rejects a body that isn't an object", async () => {
    expect((await report([1, 2, 3])).status).toBe(400);
  });

  it("requires scanner authentication", async () => {
    const res = await request(getApp()).put("/api/ingest/config-report").send({ masscanRate: 1 });
    expect(res.status).toBe(401);
  });

  it("surfaces the reported values on the agents endpoint the dialog reads", async () => {
    await report({ masscanRate: 500, nucleiConcurrency: 4 });
    const client = await loginAs(admin.username, admin.password);
    const res = await client.get("/api/agents");
    expect(res.status).toBe(200);
    const row = res.body.find((a: { id: string }) => a.id === agent.id);
    expect(row.base_config).toEqual({ masscanRate: 500, nucleiConcurrency: 4 });
  });

  it("keeps the reported file values separate from a dashboard override", async () => {
    // The dialog's question is "what applies if I leave this blank", so an
    // override must not overwrite what the file says - otherwise there
    // would be nothing left to clear back to.
    const client = await loginAs(admin.username, admin.password);
    const put = await client.put(`/api/agents/${agent.id}/config`).send({ masscanRate: 9000 });
    expect(put.status).toBe(200);

    const res = await client.get("/api/agents");
    const row = res.body.find((a: { id: string }) => a.id === agent.id);
    expect(row.config_overrides).toEqual({ masscanRate: 9000 });
    expect(row.base_config.masscanRate).toBe(500);
  });
});
