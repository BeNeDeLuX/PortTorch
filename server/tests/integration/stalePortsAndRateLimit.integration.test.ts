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

// A port that quietly stops answering never gets an explicit 'closed'
// observation - masscan only reports what it currently sees open - so
// current_host_ports keeps surfacing its last known "open" indefinitely.
// Host Detail has flagged this per port for a while; these tests cover
// making it visible and filterable fleet-wide, where the open-port counts
// otherwise silently overstate exposure.
describe("fleet-wide unconfirmed (stale) open ports", () => {
  let agent: TestAgent;
  let admin: TestUser;
  const IP = "240.21.0.5";

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
  });

  async function ingest(ports: number[]): Promise<void> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "1-1000" });
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

  it("counts only ports the latest scan did not re-confirm, and filters on them", async () => {
    agent = await createTestAgent("it-stale-agent");
    admin = await createTestUser("admin");
    const session = await loginAs(admin.username, admin.password);

    // First scan sees both ports - nothing is stale yet, which is the
    // regression that matters most: a perfectly fresh scan must not flag
    // its own ports (observed_at vs. hosts.last_seen_at would).
    await ingest([22, 8080]);
    const fresh = await session.get(`/api/hosts?q=${IP}`);
    expect(fresh.body.items[0].open_port_count).toBe(2);
    expect(fresh.body.items[0].stale_port_count).toBe(0);

    // Second scan only re-confirms 22. 8080 keeps its last "open"
    // observation and is now unconfirmed.
    await new Promise((r) => setTimeout(r, 1100));
    await ingest([22]);

    const after = await session.get(`/api/hosts?q=${IP}`);
    expect(after.body.items[0].open_port_count).toBe(2);
    expect(after.body.items[0].stale_port_count).toBe(1);

    // The count is a JS number, not the bigint-as-string node-postgres
    // hands back - this exact trap has produced two real bugs here before.
    expect(typeof after.body.items[0].stale_port_count).toBe("number");

    const filtered = await session.get(`/api/hosts?q=${IP}&hasStalePorts=true`);
    expect(filtered.body.items.map((h: { ip: string }) => h.ip)).toContain(IP);
  });

  it("excludes a host whose ports were all re-confirmed", async () => {
    const session = await loginAs(admin.username, admin.password);
    await new Promise((r) => setTimeout(r, 1100));
    await ingest([22, 8080]);

    const after = await session.get(`/api/hosts?q=${IP}`);
    expect(after.body.items[0].stale_port_count).toBe(0);

    const filtered = await session.get(`/api/hosts?q=${IP}&hasStalePorts=true`);
    expect(filtered.body.items).toHaveLength(0);
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
