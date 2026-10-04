import { sql } from "kysely";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestApiToken,
  deleteTestAgent,
  deleteTestApiToken,
  getApp,
  type TestAgent,
  type TestApiToken,
} from "./helpers";

const DAY = 24 * 60 * 60 * 1000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

// The External API's view of network changes, baselines and port policies:
// the dashboard's own data through the same service functions, scoped by
// the token's scanner restriction and gated by its scope for the one write.
describe("external API - networks, baselines, port policies", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let token: TestApiToken;
  let readOnly: TestApiToken;
  let scoped: TestApiToken;
  let baselineId: string;
  let policyId: string;
  const hostIds: string[] = [];

  const api = (t: TestApiToken) => ({
    get: (path: string) => request(getApp()).get(`/api/v1${path}`).set("Authorization", `Bearer ${t.token}`),
    post: (path: string) => request(getApp()).post(`/api/v1${path}`).set("Authorization", `Bearer ${t.token}`),
  });

  beforeAll(async () => {
    agent = await createTestAgent("it-api-net");
    other = await createTestAgent("it-api-net-other");
    token = await createTestApiToken("it-api-net");
    readOnly = await createTestApiToken("it-api-net-ro");
    scoped = await createTestApiToken("it-api-net-scoped");
    await db.updateTable("api_tokens").set({ scope: "read" }).where("id", "=", readOnly.id).execute();
    await db.updateTable("api_tokens").set({ scanner_agent_ids: [other.id] }).where("id", "=", scoped.id).execute();

    const job = (
      await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${agent.apiKey}`).send({ targetSpec: "10.94.0.0/24", portSpec: "1-1000" })
    ).body.id;
    for (const [ip, firstSeen, a] of [["10.94.0.1", 10, agent], ["10.94.0.2", 2, agent], ["10.94.0.3", 2, other]] as const) {
      const h = await db
        .insertInto("hosts")
        .values({ ip, scanner_agent_id: a.id, first_seen_at: ago(firstSeen) })
        .returning("id")
        .executeTakeFirstOrThrow();
      hostIds.push(h.id);
      await db
        .insertInto("host_port_observations")
        .values({ host_id: h.id, scan_job_id: job, port: 3389, protocol: "tcp", state: "open", observed_at: ago(firstSeen) })
        .execute();
    }
    baselineId = (
      await db
        .insertInto("network_baselines")
        .values({ network: "10.94.0.0/24", approved_at: ago(5), approved_by: "it" })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;
    policyId = (
      await db
        .insertInto("port_policies")
        .values({ name: "it no rdp", network: "10.94.0.0/24", mode: "deny", ports: "3389" })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;
  });

  afterAll(async () => {
    await db.deleteFrom("network_baselines").where("id", "=", baselineId).execute();
    await db.deleteFrom("port_policies").where("id", "=", policyId).execute();
    await db.deleteFrom("hosts").where("id", "in", hostIds).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    for (const t of [token, readOnly, scoped]) await deleteTestApiToken(t.id);
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    await closeDb();
  });

  it("reports what changed in a network, narrowed by scanner name", async () => {
    const res = await api(token).get(`/networks/changes?network=10.94.0&from=${encodeURIComponent(ago(5))}`);
    expect(res.status).toBe(200);
    expect(res.body.network).toBe("10.94.0.0/24");
    expect(res.body.newHosts.items.map((h: { ip: string }) => h.ip).sort()).toEqual(["10.94.0.2", "10.94.0.3"]);

    const narrowed = await api(token).get(`/networks/changes?network=10.94.0&from=${encodeURIComponent(ago(5))}&scannerAgent=${other.name}`);
    expect(narrowed.body.newHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["10.94.0.3"]);
    expect((await api(token).get("/networks/changes?network=10.94.0&scannerAgent=nope")).status).toBe(400);
    expect((await api(token).get("/networks/changes?network=intranet")).status).toBe(400);
    expect((await api(token).get("/networks/changes?network=10.94.0&from=yesterday")).status).toBe(400);
  });

  it("lists baselines and their deviations, and approves with a read-write token only", async () => {
    const list = await api(readOnly).get("/baselines");
    expect(list.body.find((b: { id: string }) => b.id === baselineId).deviations).toMatchObject({ newHosts: 2 });
    const detail = await api(readOnly).get(`/baselines/${baselineId}`);
    expect(detail.body.changes.newHosts.items).toHaveLength(2);

    expect((await api(readOnly).post(`/baselines/${baselineId}/approve`).send({})).status).toBe(403);
    expect((await api(token).post(`/baselines/${baselineId}/approve`).send({ note: "CHG-1234 closed" })).status).toBe(204);
    const row = await db.selectFrom("network_baselines").select(["approved_by", "note"]).where("id", "=", baselineId).executeTakeFirstOrThrow();
    expect(row).toEqual({ approved_by: `api-token:${token.name}`, note: "CHG-1234 closed" });
    const audit = await db
      .selectFrom("audit_log")
      .select("actor")
      .where("event", "=", "baseline.approved")
      .where(sql<boolean>`details->>'baseline_id' = ${baselineId}`)
      .executeTakeFirst();
    expect(audit?.actor).toBe(`api-token:${token.name}`);
    expect((await api(token).get("/baselines/not-a-uuid")).status).toBe(404);
  });

  it("lists port policies and their violations", async () => {
    const list = await api(readOnly).get("/port-policies");
    expect(list.body.find((p: { id: string }) => p.id === policyId)).toMatchObject({ violations: 3, violatingHosts: 3 });
    const detail = await api(readOnly).get(`/port-policies/${policyId}`);
    expect(detail.body.violations.items.map((v: { ip: string }) => v.ip)).toEqual(["10.94.0.1", "10.94.0.2", "10.94.0.3"]);
  });

  it("narrows everything to a restricted token's scanners", async () => {
    const changes = await api(scoped).get(`/networks/changes?network=10.94.0&from=${encodeURIComponent(ago(30))}`);
    expect(changes.body.newHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["10.94.0.3"]);
    const policy = await api(scoped).get(`/port-policies/${policyId}`);
    expect(policy.body.violations.items.map((v: { ip: string }) => v.ip)).toEqual(["10.94.0.3"]);
  });
});
