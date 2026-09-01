import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { sql } from "kysely";
import { db } from "../../src/db";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";
import crypto from "crypto";
import { hashApiKey } from "../../src/ingest/apiKeyAuth";

const IP_A = "240.80.0.1";
const IP_B = "240.80.0.2";

// A token used to be a name and an expiry and nothing else, while the API
// it unlocks can trigger rescans, cancel scans, queue ad-hoc scans and
// delete triage decisions. A token handed to a reporting script could
// therefore launch scans across the network.
describe("API token scopes and scanner restriction", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  const tokens: Record<string, string> = {};
  const tokenIds: string[] = [];

  async function makeToken(name: string, scope: string, scannerAgentIds: string[] = []): Promise<string> {
    const secret = crypto.randomBytes(16).toString("hex");
    const row = await db
      .insertInto("api_tokens")
      .values({
        name: `${name}-${Date.now()}`,
        token_hash: hashApiKey(secret),
        created_by: "it",
        scope,
        scanner_agent_ids: scannerAgentIds,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    tokenIds.push(row.id);
    return secret;
  }

  beforeAll(async () => {
    agentA = await createTestAgent("it-scope-a");
    agentB = await createTestAgent("it-scope-b");
    for (const [ip, agent] of [
      [IP_A, agentA],
      [IP_B, agentB],
    ] as const) {
      await db.insertInto("hosts").values({ ip, scanner_agent_id: agent.id }).execute();
    }
    tokens.read = await makeToken("it-read", "read");
    tokens.write = await makeToken("it-write", "read_write");
    tokens.scopedToA = await makeToken("it-scoped", "read", [agentA.id]);
  });

  afterAll(async () => {
    await db.deleteFrom("api_tokens").where("id", "in", tokenIds).execute();
    await sql`DELETE FROM hosts WHERE ip = ${IP_A}::inet OR ip = ${IP_B}::inet`.execute(db);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await closeDb();
  });

  const get = (path: string, token: string) =>
    request(getApp()).get(path).set("Authorization", `Bearer ${token}`);
  const post = (path: string, token: string) =>
    request(getApp()).post(path).set("Authorization", `Bearer ${token}`);

  it("lets a read token read", async () => {
    const res = await get(`/api/v1/hosts?q=${IP_A}`, tokens.read);
    expect(res.status).toBe(200);
    expect(res.body.items).toHaveLength(1);
  });

  it("refuses every state-changing endpoint for a read token", async () => {
    // The whole point: these are what a token must not be able to do just
    // because someone needed it to read.
    const rescan = await post("/api/v1/hosts/rescan", tokens.read).send({ ip: IP_A });
    expect(rescan.status).toBe(403);
    expect(String(rescan.body.error)).toContain("read-only");

    expect((await post("/api/v1/hosts/cancel-scan", tokens.read).send({ ip: IP_A })).status).toBe(403);
    expect(
      (await post("/api/v1/scans/adhoc", tokens.read).send({ scannerAgent: agentA.name, targetSpec: IP_A, portSpec: "80" }))
        .status
    ).toBe(403);
    const del = await request(getApp())
      .delete("/api/v1/findings/triage")
      .set("Authorization", `Bearer ${tokens.read}`)
      .send({ ip: IP_A, kind: "cve", cveId: "CVE-2020-0001" });
    expect(del.status).toBe(403);
  });

  it("still allows a read_write token through the guard", async () => {
    // 403 is what's under test; anything else means it got past the scope
    // check and failed on its own merits, which is the correct outcome.
    const res = await post("/api/v1/hosts/rescan", tokens.write).send({ ip: IP_A });
    expect(res.status).not.toBe(403);
  });

  it("confines a scanner-restricted token to that scanner's hosts", async () => {
    const list = await get("/api/v1/hosts", tokens.scopedToA);
    expect(list.status).toBe(200);
    const ips = list.body.items.map((h: { ip: string }) => h.ip);
    expect(ips).toContain(IP_A);
    expect(ips).not.toContain(IP_B);
  });

  it("applies the restriction to lookup too, not just the list", async () => {
    // A restriction that only covered the list would be no restriction at
    // all - lookup returns the same host by another route.
    expect((await get(`/api/v1/hosts/lookup?ip=${IP_A}`, tokens.scopedToA)).status).toBe(200);
    expect((await get(`/api/v1/hosts/lookup?ip=${IP_B}`, tokens.scopedToA)).status).toBe(404);
    // An unrestricted token still sees both.
    expect((await get(`/api/v1/hosts/lookup?ip=${IP_B}`, tokens.read)).status).toBe(200);
  });

  it("defaults a token created before scopes existed to read_write", async () => {
    // The column default, not the dashboard's - a migration must not
    // silently break integrations that work today.
    const row = await db
      .insertInto("api_tokens")
      .values({ name: `it-legacy-${Date.now()}`, token_hash: hashApiKey(crypto.randomBytes(16).toString("hex")), created_by: "it" })
      .returning(["id", "scope", "scanner_agent_ids"])
      .executeTakeFirstOrThrow();
    tokenIds.push(row.id);
    expect(row.scope).toBe("read_write");
    expect(row.scanner_agent_ids).toEqual([]);
  });
});
