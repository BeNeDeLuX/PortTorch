import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { sql } from "kysely";
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

const NET = "240.32.0.0/24";

describe("saved search matches", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let operator: TestUser;
  let client: SessionClient;
  let searchId: string;
  let hostA: string;
  let hostB: string;

  beforeAll(async () => {
    agentA = await createTestAgent("it-ssm-a");
    agentB = await createTestAgent("it-ssm-b");
    operator = await createTestUser("operator");
    client = await loginAs(operator.username, operator.password);

    for (const [ip, agent] of [
      ["240.32.0.1", agentA],
      ["240.32.0.2", agentB],
    ] as const) {
      const job = await request(getApp())
        .post("/api/ingest/scan-jobs")
        .set("Authorization", `Bearer ${agent.apiKey}`)
        .send({ targetSpec: NET, portSpec: "443" });
      await request(getApp())
        .post("/api/ingest/hosts")
        .set("Authorization", `Bearer ${agent.apiKey}`)
        .send({ scanJobId: job.body.id, hosts: [{ ip, ports: [{ port: 443, protocol: "tcp", state: "open" }] }] });
    }
    hostA = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", "240.32.0.1").executeTakeFirstOrThrow()).id;
    hostB = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", "240.32.0.2").executeTakeFirstOrThrow()).id;

    const created = await client.post("/api/saved-searches").send({ name: "it-ssm-search", filters: { port: "443" } });
    expect(created.status).toBe(201);
    searchId = created.body.id;

    // Written the way the periodic checker writes it - this endpoint
    // deliberately reports that record rather than re-running the query.
    await db
      .insertInto("saved_search_matches")
      .values([
        { saved_search_id: searchId, host_id: hostA },
        { saved_search_id: searchId, host_id: hostB },
      ])
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("saved_searches").where("id", "=", searchId).execute();
    await sql`DELETE FROM hosts WHERE ip <<= ${NET}::cidr`.execute(db);
    await db.deleteFrom("scan_jobs").where("target_spec", "=", NET).execute();
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  it("reports what the checker last matched, per search", async () => {
    const res = await client.get("/api/saved-searches/matches");
    expect(res.status).toBe(200);
    const entry = res.body.find((m: { savedSearchId: string }) => m.savedSearchId === searchId);
    expect(entry).toBeDefined();
    expect(entry.matchCount).toBe(2);
    expect(entry.hosts.map((h: { ip: string }) => h.ip).sort()).toEqual(["240.32.0.1", "240.32.0.2"]);
  });

  it("never counts a host from a scanner the session cannot see", async () => {
    const restricted = await createTestUser("operator");
    try {
      await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: agentA.id }).execute();
      const restrictedClient = await loginAs(restricted.username, restricted.password);
      const res = await restrictedClient.get("/api/saved-searches/matches");
      expect(res.status).toBe(200);
      const entry = res.body.find((m: { savedSearchId: string }) => m.savedSearchId === searchId);
      // Both hosts match the search, but only one belongs to a scanner
      // this session is assigned to - so the count has to shrink with it,
      // not just the host list.
      expect(entry.matchCount).toBe(1);
      expect(entry.hosts[0].ip).toBe("240.32.0.1");
    } finally {
      await deleteTestUser(restricted.id);
    }
  });
});
