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
  type TestAgent,
  type TestUser,
} from "./helpers";

// Class E (240.0.0.0/4) - reserved, so nothing here can collide with real
// data when the suite runs against a copy of a production database.
const NETWORK = "240.20.0.0/24";

interface CoverageRow {
  id: string;
  label: string;
  cidr: string;
  address_count: number;
  host_count: number;
  recent_host_count: number;
  last_covered_at: string | null;
  covered_fraction: number;
  opaque_scan_count: number;
}

async function completedScan(agent: TestAgent, targetSpec: string, hostIps: string[] = []): Promise<void> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec, portSpec: "80" });
  expect(jobRes.status).toBe(201);

  if (hostIps.length > 0) {
    const hostsRes = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: hostIps.map((ip) => ({ ip, ports: [{ port: 80, protocol: "tcp", state: "open" }] })),
      });
    expect(hostsRes.status).toBe(204);
  }

  const doneRes = await request(getApp())
    .patch(`/api/ingest/scan-jobs/${jobRes.body.id}`)
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ status: "completed" });
  expect(doneRes.status).toBe(204);
}

describe("network coverage", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let networkId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-coverage");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
  });

  afterAll(async () => {
    await db.deleteFrom("monitored_networks").where("label", "like", "it-coverage%").execute();
    for (const spec of ["240.20.0.0/25", "240.20.0.7", "240.21.0.0/24", "coverage.internal"]) {
      await db.deleteFrom("scan_jobs").where("target_spec", "=", spec).execute();
    }
    await sql`DELETE FROM hosts WHERE ip <<= '240.20.0.0/24'::cidr`.execute(db);
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    await closeDb();
  });

  async function coverage(client: Awaited<ReturnType<typeof loginAs>>): Promise<CoverageRow> {
    const res = await client.get("/api/networks");
    expect(res.status).toBe(200);
    const row = res.body.networks.find((n: CoverageRow) => n.id === networkId);
    expect(row).toBeDefined();
    return row;
  }

  it("only lets an admin declare a tracked range", async () => {
    const operatorClient = await loginAs(operator.username, operator.password);
    const denied = await operatorClient.post("/api/networks").send({ label: "it-coverage-denied", cidr: NETWORK });
    expect(denied.status).toBe(403);

    const adminClient = await loginAs(admin.username, admin.password);
    const created = await adminClient.post("/api/networks").send({ label: "it-coverage-net", cidr: NETWORK });
    expect(created.status).toBe(201);
    expect(created.body.cidr).toBe(NETWORK);
    networkId = created.body.id;
  });

  it("rejects anything that is not an IPv4 CIDR", async () => {
    const client = await loginAs(admin.username, admin.password);
    for (const cidr of ["240.20.1.1", "240.20.1.1-240.20.1.9", "2001:db8::/32", "nonsense"]) {
      const res = await client.post("/api/networks").send({ label: "it-coverage-bad", cidr });
      expect(res.status).toBe(400);
    }
  });

  it("starts at zero coverage with no scan history", async () => {
    const client = await loginAs(admin.username, admin.password);
    const row = await coverage(client);
    expect(row.address_count).toBe(256);
    expect(row.covered_fraction).toBe(0);
    expect(row.last_covered_at).toBeNull();
    expect(row.host_count).toBe(0);
  });

  it("counts a half-range sweep as half covered, not as covered", async () => {
    await completedScan(agent, "240.20.0.0/25", ["240.20.0.7"]);

    const client = await loginAs(admin.username, admin.password);
    const row = await coverage(client);
    expect(row.covered_fraction).toBeCloseTo(0.5, 10);
    expect(row.last_covered_at).not.toBeNull();
    expect(row.host_count).toBe(1);
    expect(row.recent_host_count).toBe(1);
  });

  it("does not let a single-host rescan inflate coverage of the whole range", async () => {
    // A /32 inside the already-swept half adds nothing: the union is
    // still exactly the /25.
    await completedScan(agent, "240.20.0.7");

    const client = await loginAs(admin.username, admin.password);
    const row = await coverage(client);
    expect(row.covered_fraction).toBeCloseTo(0.5, 10);
  });

  it("ignores scans of an unrelated range", async () => {
    await completedScan(agent, "240.21.0.0/24");

    const client = await loginAs(admin.username, admin.password);
    const row = await coverage(client);
    expect(row.covered_fraction).toBeCloseTo(0.5, 10);
  });

  it("reports a hostname target as opaque instead of guessing", async () => {
    // The scanner resolves hostnames, so the webserver genuinely cannot
    // tell which addresses this covered - it must not be counted either
    // way, only surfaced.
    await completedScan(agent, "coverage.internal");

    const client = await loginAs(admin.username, admin.password);
    const row = await coverage(client);
    expect(row.opaque_scan_count).toBeGreaterThanOrEqual(1);
    expect(row.covered_fraction).toBeCloseTo(0.5, 10);
  });

  it("rejects a duplicate range, including one written non-normalised", async () => {
    const client = await loginAs(admin.username, admin.password);
    const exact = await client.post("/api/networks").send({ label: "it-coverage-dup", cidr: NETWORK });
    expect(exact.status).toBe(409);
    // Postgres normalises 240.20.0.37/24 to 240.20.0.0/24 - comparing as
    // cidr rather than text is what catches this.
    const nonNormalised = await client.post("/api/networks").send({ label: "it-coverage-dup", cidr: "240.20.0.37/24" });
    expect(nonNormalised.status).toBe(409);
  });

  it("lets an admin delete a tracked range", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.delete(`/api/networks/${networkId}`);
    expect(res.status).toBe(204);

    const after = await client.get("/api/networks");
    expect(after.body.networks.find((n: CoverageRow) => n.id === networkId)).toBeUndefined();
  });
});
