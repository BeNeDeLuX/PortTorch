import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type TestAgent, type TestUser } from "./helpers";

// Two different IPs (not just two hostnames on one ip) so each gets its
// own hosts row on the same scanner agent - identity is (ip,
// scanner_agent_id), so reusing one ip for both would just upsert into a
// single host instead of two distinguishable ones.
const IP_ALPHA = "240.1.9.10";
const IP_BETA = "240.1.9.11";

interface PortFacetRow {
  port: number;
  count: number;
}

// The bug this covers: GET /api/hosts/facets and /api/hosts/facets/ports
// used to ignore the request's query params entirely (`_req`) - the Ports
// sidebar always showed fleet-wide counts no matter what the dashboard's
// own keyword search or other filters currently narrowed the host list
// down to, so the sidebar looked "stuck" instead of live-updating.
describe("host facets are scoped to the current search filters", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: Awaited<ReturnType<typeof loginAs>>;
  let suffix: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-facets-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    suffix = Math.random().toString(36).slice(2, 8);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: `${IP_ALPHA}-${IP_BETA}`, portSpec: "61234-61235" });
    const scanJobId = jobRes.body.id;

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId,
        hosts: [
          {
            ip: IP_ALPHA,
            hostname: `facetprobe-alpha-${suffix}.internal`,
            ports: [{ port: 61234, protocol: "tcp", state: "open", serviceName: `facetprobe-svc-alpha-${suffix}` }],
          },
          {
            ip: IP_BETA,
            hostname: `facetprobe-beta-${suffix}.internal`,
            ports: [{ port: 61235, protocol: "tcp", state: "open", serviceName: `facetprobe-svc-beta-${suffix}` }],
          },
        ],
      });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "in", [IP_ALPHA, IP_BETA]).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  it("shows both ports when unfiltered", async () => {
    const res = await client.get("/api/hosts/facets/ports");
    expect(res.status).toBe(200);
    const ports: PortFacetRow[] = res.body;
    expect(ports.find((p) => p.port === 61234)).toMatchObject({ count: 1 });
    expect(ports.find((p) => p.port === 61235)).toMatchObject({ count: 1 });
  });

  it("narrows the ports facet down to only the matching host once a keyword search is active", async () => {
    const res = await client.get(`/api/hosts/facets/ports?q=facetprobe-alpha-${suffix}`);
    expect(res.status).toBe(200);
    const ports: PortFacetRow[] = res.body;
    expect(ports.find((p) => p.port === 61234)).toMatchObject({ count: 1 });
    expect(ports.find((p) => p.port === 61235)).toBeUndefined();
  });

  it("scopes services/ports/tags on the main /facets response the same way", async () => {
    const res = await client.get(`/api/hosts/facets?q=facetprobe-beta-${suffix}`);
    expect(res.status).toBe(200);
    expect(res.body.ports.find((p: PortFacetRow) => p.port === 61235)).toMatchObject({ count: 1 });
    expect(res.body.ports.find((p: PortFacetRow) => p.port === 61234)).toBeUndefined();
    expect(res.body.services.find((s: { service: string }) => s.service === `facetprobe-svc-beta-${suffix}`)).toMatchObject({ count: 1 });
    expect(res.body.services.find((s: { service: string }) => s.service === `facetprobe-svc-alpha-${suffix}`)).toBeUndefined();
  });

  it("keeps a facet's own alternatives visible when one of its own values is already selected", async () => {
    // Selecting port 61234 (alpha's port) shouldn't hide port 61235 from
    // the ports facet itself - only the *other* active filters (q, tags,
    // etc.) narrow a facet's own dimension, not the facet's own selection,
    // otherwise a user could never see what else they could add.
    const res = await client.get("/api/hosts/facets/ports?port=61234");
    expect(res.status).toBe(200);
    const ports: PortFacetRow[] = res.body;
    expect(ports.find((p) => p.port === 61234)).toMatchObject({ count: 1 });
    expect(ports.find((p) => p.port === 61235)).toMatchObject({ count: 1 });
  });
});
