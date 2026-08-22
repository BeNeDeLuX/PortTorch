import { afterAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { config } from "../../src/config";
import { resetApiTokenRateLimits } from "../../src/apiTokens/rateLimit";
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

// The scanner has exposed /metrics all along while the webserver - the
// component holding every bit of state and running a dozen background
// tickers - exposed nothing at all, so the half of the system most worth
// monitoring was the half you couldn't.
describe("webserver health and metrics", () => {
  const originalToken = config.metricsToken;

  afterAll(() => {
    config.metricsToken = originalToken;
  });

  it("serves /healthz without any credential", async () => {
    const res = await request(getApp()).get("/healthz");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.database).toBe("ok");
    expect(res.body.version).toBeTruthy();
  });

  // Fail-closed: an operator who never considered this endpoint must not
  // silently publish fleet counts by upgrading.
  it("404s /metrics when no token is configured, rather than serving it openly", async () => {
    config.metricsToken = "";
    const res = await request(getApp()).get("/metrics");
    expect(res.status).toBe(404);
  });

  it("requires the configured bearer token", async () => {
    config.metricsToken = "metrics-secret";
    expect((await request(getApp()).get("/metrics")).status).toBe(401);
    expect((await request(getApp()).get("/metrics").set("Authorization", "Bearer wrong")).status).toBe(401);
  });

  it("serves valid Prometheus exposition with numeric values", async () => {
    config.metricsToken = "metrics-secret";
    const res = await request(getApp()).get("/metrics").set("Authorization", "Bearer metrics-secret");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/plain/);
    expect(res.text).toContain("porttorch_build_info");
    expect(res.text).toContain("porttorch_hosts_total");

    // Every sample line must end in a real number. Counts come back from
    // node-postgres as bigint strings, and an unconverted one would emit
    // syntactically valid but wrong output - or NaN - which a scrape
    // would reject. This is the third place that trap has mattered.
    const samples = res.text.split("\n").filter((l) => l && !l.startsWith("#"));
    expect(samples.length).toBeGreaterThan(5);
    for (const line of samples) {
      const value = line.slice(line.lastIndexOf(" ") + 1);
      expect(Number.isFinite(Number(value))).toBe(true);
      expect(value).not.toBe("NaN");
    }
  });
});

// Every other route in this router needs the caller to already know an ip
// or hostname, which rules out exactly the jobs the API exists for.
describe("external API - GET /hosts", () => {
  let agent: TestAgent;
  let token: TestApiToken;
  const IPS = ["240.31.0.1", "240.31.0.2", "240.31.0.3"];

  afterAll(async () => {
    for (const ip of IPS) await db.deleteFrom("hosts").where("ip", "=", ip).execute();
    await deleteTestAgent(agent.id);
    await deleteTestApiToken(token.id);
    resetApiTokenRateLimits();
    await closeDb();
  });

  async function seed(): Promise<void> {
    agent = await createTestAgent("it-hostlist-agent");
    token = await createTestApiToken("it-hostlist-token");
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: "240.31.0.0/24", portSpec: "1-100" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [
          { ip: IPS[0], ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] },
          { ip: IPS[1], ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https" }] },
          { ip: IPS[2], ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] },
        ],
      });
  }

  const list = (qs = "") =>
    request(getApp()).get(`/api/v1/hosts${qs}`).set("Authorization", `Bearer ${token.token}`);

  it("lists hosts with a total, and paginates", async () => {
    await seed();
    const all = await list();
    expect(all.status).toBe(200);
    expect(all.body.total).toBeGreaterThanOrEqual(3);
    expect(all.body.page).toBe(1);
    expect(Array.isArray(all.body.items)).toBe(true);

    const paged = await list("?pageSize=1&page=1");
    expect(paged.body.items).toHaveLength(1);
    expect(paged.body.pageSize).toBe(1);
    // total describes the whole match set, not the page.
    expect(paged.body.total).toBe(all.body.total);

    const second = await list("?pageSize=1&page=2");
    expect(second.body.items[0].id).not.toBe(paged.body.items[0].id);
  });

  // The point of reusing applyHostFilters: a parameter means the same
  // thing here as in the dashboard's own URL.
  it("honours the dashboard's filter parameters", async () => {
    const byPort = await list("?port=443");
    expect(byPort.status).toBe(200);
    const ips = byPort.body.items.map((h: { ip: string }) => h.ip);
    expect(ips).toContain(IPS[1]);
    expect(ips).not.toContain(IPS[0]);

    const byQuery = await list(`?q=${IPS[2]}`);
    expect(byQuery.body.items.map((h: { ip: string }) => h.ip)).toEqual([IPS[2]]);
  });

  it("caps pageSize rather than allowing an unbounded dump", async () => {
    const res = await list("?pageSize=5000");
    expect(res.status).toBe(400);
  });

  it("requires a token", async () => {
    expect((await request(getApp()).get("/api/v1/hosts")).status).toBe(401);
  });

  it("returns ip as a plain string, and includes the owning scanner", async () => {
    const res = await list(`?q=${IPS[0]}`);
    const host = res.body.items[0];
    expect(typeof host.ip).toBe("string");
    expect(host.ip).toBe(IPS[0]);
    expect(host.scanner_agent_name).toBe(agent.name);
  });
});
