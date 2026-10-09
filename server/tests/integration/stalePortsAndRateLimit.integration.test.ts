import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { config } from "../../src/config";
import { resetApiTokenRateLimits } from "../../src/apiTokens/rateLimit";
import {
  closeDb,
  createTestAgent,
  createTestApiToken,
  createTestUser,
  deleteTestAgent,
  deleteTestApiToken,
  deleteTestUser,
  getApp,
  loginAs,
  type TestAgent,
  type TestApiToken,
  type TestUser,
} from "./helpers";

// An open port keeps its last "open" observation until a scan that covers
// it records it closed - so one in a range nobody rescans stays "open"
// indefinitely. It is flagged "unconfirmed" once no scan has confirmed it
// for app_settings.unconfirmed_port_days. Deliberately by age: a scan of
// other ports says nothing about it, and targeted single-port scans must
// never flag the rest of a host.
describe("fleet-wide unconfirmed (stale) open ports", () => {
  let agent: TestAgent;
  let admin: TestUser;
  const IP = "240.21.0.5";

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
  });

  async function ingest(ports: number[], portSpec = "1-10000"): Promise<void> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          {
            ip: IP,
            ports: ports.map((port) => ({ port, protocol: "tcp", state: "open", serviceName: "x" })),
          },
        ],
      });
  }

  const hostRow = async (session: Awaited<ReturnType<typeof loginAs>>) => (await session.get(`/api/hosts?q=${IP}`)).body.items[0];

  it("never flags the rest of a host because a scan asked about other ports", async () => {
    agent = await createTestAgent("it-stale-agent");
    admin = await createTestUser("admin");
    const session = await loginAs(admin.username, admin.password);

    await ingest([22, 25, 8080]);
    expect(await hostRow(session)).toMatchObject({ open_port_count: 3, stale_port_count: 0 });

    // The reported case: targeted scans of single ports, one at a time.
    // Each only speaks for its own port; the others keep their state.
    await new Promise((r) => setTimeout(r, 1100));
    await ingest([80], "80");
    await ingest([143], "143");
    const after = await hostRow(session);
    expect(after.open_port_count).toBe(5);
    expect(after.stale_port_count).toBe(0);
    // The count is a JS number, not the bigint-as-string node-postgres
    // hands back - this exact trap has produced real bugs here before.
    expect(typeof after.stale_port_count).toBe("number");
    expect((await session.get(`/api/hosts?q=${IP}&hasStalePorts=true`)).body.items).toHaveLength(0);
  });

  it("flags a port no scan has confirmed within the configured days, and reads the setting live", async () => {
    const session = await loginAs(admin.username, admin.password);
    const host = await db.selectFrom("hosts").select("id").where("ip", "=", IP).executeTakeFirstOrThrow();
    await db
      .updateTable("host_port_observations")
      .set({ observed_at: new Date(Date.now() - 40 * 86_400_000).toISOString() })
      .where("host_id", "=", host.id)
      .where("port", "=", 8080)
      .execute();

    expect((await hostRow(session)).stale_port_count).toBe(1);
    expect((await session.get(`/api/hosts?q=${IP}&hasStalePorts=true`)).body.items.map((h: { ip: string }) => h.ip)).toContain(IP);

    // A longer limit applies on the very next request.
    expect((await session.patch("/api/settings/app").send({ unconfirmedPortDays: 60 })).status).toBe(200);
    expect((await hostRow(session)).stale_port_count).toBe(0);
    await session.patch("/api/settings/app").send({ unconfirmedPortDays: 30 });
  });

  it("clears once a scan that covers the port confirms it - or records it closed", async () => {
    const session = await loginAs(admin.username, admin.password);
    // A scan covering 8080 that no longer finds it records it closed, so
    // it is neither open nor unconfirmed any more.
    await ingest([22], "22,8080");
    const after = await hostRow(session);
    expect(after.open_port_count).toBe(4);
    expect(after.stale_port_count).toBe(0);
  });
});

// Every External API call runs real fleet-wide SQL, so a runaway or
// misconfigured integration polling in a loop degrades the dashboard for
// everyone. This is throughput limiting, distinct from the failure-based
// login lockout - none of these are failed authentications.
describe("external API rate limiting", () => {
  let token: TestApiToken;
  const original = config.apiTokenRateLimitPerMinute;

  afterAll(async () => {
    config.apiTokenRateLimitPerMinute = original;
    resetApiTokenRateLimits();
    await deleteTestApiToken(token.id);
    await closeDb();
  });

  const call = () =>
    request(getApp()).get("/api/v1/hosts/lookup?ip=240.21.9.9").set("Authorization", `Bearer ${token.token}`);

  it("serves budget headers and 429s past the limit, with Retry-After", async () => {
    token = await createTestApiToken("it-ratelimit-token");
    config.apiTokenRateLimitPerMinute = 3;
    resetApiTokenRateLimits();

    // 404 is the expected body here (no such host) - what's under test is
    // that the request was allowed through to the route at all.
    const first = await call();
    expect(first.headers["x-ratelimit-limit"]).toBe("3");
    expect(first.headers["x-ratelimit-remaining"]).toBe("2");
    expect(first.status).not.toBe(429);

    await call();
    await call();

    const blocked = await call();
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toMatch(/rate limit/i);
    expect(Number(blocked.headers["retry-after"])).toBeGreaterThan(0);
  });

  // A throttled caller must not be mistaken for an unauthenticated one -
  // 429 and 401 mean very different things to a client's retry logic.
  it("still rejects a bad token with 401, not 429, while limited", async () => {
    const res = await request(getApp())
      .get("/api/v1/hosts/lookup?ip=240.21.9.9")
      .set("Authorization", "Bearer not-a-real-token");
    expect(res.status).toBe(401);
  });

  it("does not limit at all when configured to 0", async () => {
    config.apiTokenRateLimitPerMinute = 0;
    resetApiTokenRateLimits();
    for (let i = 0; i < 10; i++) {
      expect((await call()).status).not.toBe(429);
    }
  });
});
