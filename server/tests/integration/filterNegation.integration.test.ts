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

// 240.0.0.0/4 is reserved and never routable - can't collide with real
// data if this suite is ever run against a copy of a live database.
const DNS_HOST = "240.11.0.1";
const WEB_HOST = "240.11.0.2";
const BOTH_HOST = "240.11.0.3";
const CLOSED_53_HOST = "240.11.0.4";

// A leading "-" on a filter value excludes instead of including. The
// interesting cases aren't "does it exclude" but the two that are easy to
// get wrong: combining an include and an exclude in one parameter, and
// not excluding a host whose port 53 is merely *known and closed*.
describe("negated host filters", () => {
  let agent: TestAgent;
  let user: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-negation-agent");
    user = await createTestUser("user");
    client = await loginAs(user.username, user.password);

    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.11.0.0/24", portSpec: "53,80" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          { ip: DNS_HOST, ports: [{ port: 53, protocol: "tcp", state: "open", serviceName: "domain" }] },
          { ip: WEB_HOST, ports: [{ port: 80, protocol: "tcp", state: "open", serviceName: "http" }] },
          {
            ip: BOTH_HOST,
            ports: [
              { port: 53, protocol: "tcp", state: "open", serviceName: "domain" },
              { port: 80, protocol: "tcp", state: "open", serviceName: "http" },
            ],
          },
          {
            ip: CLOSED_53_HOST,
            ports: [
              { port: 53, protocol: "tcp", state: "closed" },
              { port: 80, protocol: "tcp", state: "open", serviceName: "http" },
            ],
          },
        ],
      });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(user.id);
    await closeDb();
  });

  async function ips(query: string): Promise<string[]> {
    const res = await client.get(`/api/hosts?${query}&pageSize=200`);
    expect(res.status).toBe(200);
    return (res.body.items as Array<{ ip: string }>)
      .map((h) => h.ip)
      .filter((ip) => ip.startsWith("240.11.0."))
      .sort();
  }

  it("still includes normally, unchanged by the negation support", async () => {
    expect(await ips("port=53")).toEqual([DNS_HOST, BOTH_HOST].sort());
  });

  it("excludes hosts with a minus-prefixed port", async () => {
    expect(await ips("port=-53")).toEqual([WEB_HOST, CLOSED_53_HOST].sort());
  });

  it("does not exclude a host whose port 53 is known but closed", async () => {
    // The subtle one: without the state = 'open' condition on the NOT
    // EXISTS side, this host would vanish from "-53" even though its DNS
    // port is shut - the opposite of what the filter is asking for.
    expect(await ips("port=-53")).toContain(CLOSED_53_HOST);
  });

  it("combines an include and an exclude in the same parameter", async () => {
    // "has 80 open and does not have 53 open"
    expect(await ips("port=80,-53")).toEqual([WEB_HOST, CLOSED_53_HOST].sort());
  });

  it("negates a service filter", async () => {
    expect(await ips("service=-domain")).toEqual([WEB_HOST, CLOSED_53_HOST].sort());
  });

  it("negates a tag filter", async () => {
    const host = await db
      .selectFrom("hosts")
      .select(["id"])
      .where("ip", "=", WEB_HOST)
      .where("scanner_agent_id", "=", agent.id)
      .executeTakeFirstOrThrow();
    await db.insertInto("host_tags").values({ host_id: host.id, tag: "it-negation-tag" }).execute();

    expect(await ips("tag=it-negation-tag")).toEqual([WEB_HOST]);
    expect(await ips("tag=-it-negation-tag")).not.toContain(WEB_HOST);
  });

  it("ignores a bare '-' rather than treating it as an empty exclusion", async () => {
    // Would otherwise exclude everything, or nothing, depending on how the
    // empty string happened to compare.
    expect(await ips("port=-")).toEqual([DNS_HOST, WEB_HOST, BOTH_HOST, CLOSED_53_HOST].sort());
  });

  it("applies to the CSV export too, which shares the same filter code", async () => {
    const res = await client.get("/api/hosts/export.csv?port=-53");
    expect(res.status).toBe(200);
    expect(res.text).toContain(WEB_HOST);
    expect(res.text).not.toContain(DNS_HOST);
  });

  it("applies to the External API's host list", async () => {
    // Same parseHostFilterParams/applyHostFilters pair, so this is really
    // asserting that the shared path stayed shared.
    const token = `it-neg-token-${Date.now()}`;
    const created = await db
      .insertInto("api_tokens")
      .values({ name: token, token_hash: (await import("node:crypto")).createHash("sha256").update(token).digest("hex") })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    try {
      const res = await request(getApp()).get("/api/v1/hosts?port=-53&pageSize=200").set("Authorization", `Bearer ${token}`);
      expect(res.status).toBe(200);
      const listed = (res.body.items as Array<{ ip: string }>).map((h) => h.ip);
      expect(listed).toContain(WEB_HOST);
      expect(listed).not.toContain(DNS_HOST);
    } finally {
      await db.deleteFrom("api_tokens").where("id", "=", created.id).execute();
    }
  });
});
