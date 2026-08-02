import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
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

// Class E (240.0.0.0/4) - reserved, never a real target on any real
// network, so it can't collide with genuine data when this suite runs
// against a copy of a real database (as it was during development).
const SHARED_IP = "240.1.2.3";

interface HostRow {
  id: string;
  ip: string;
  scanner_agent_name: string | null;
}

async function createScanJob(agent: TestAgent): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: SHARED_IP, portSpec: "80" });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function submitHost(agent: TestAgent, scanJobId: string, port: number) {
  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({
      scanJobId,
      hosts: [{ ip: SHARED_IP, hostname: `${agent.name}.internal`, ports: [{ port, protocol: "tcp", state: "open" }] }],
    });
  expect(res.status).toBe(204);
}

// The bug this covers: hosts.ip used to be globally UNIQUE with no
// scanner scoping, so two scanners in two different, non-interconnected
// networks that both happen to have a real device at the same ip (very
// common with overlapping RFC1918 ranges) would silently merge into one
// hosts row - ports/screenshots/tags from two unrelated physical devices
// blended together. Identity is now (ip, scanner_agent_id).
describe("host identity is scoped per scanner agent, not just ip", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let admin: TestUser;
  let apiToken: TestApiToken;

  beforeAll(async () => {
    agentA = await createTestAgent("it-identity-a");
    agentB = await createTestAgent("it-identity-b");
    admin = await createTestUser("admin");
    apiToken = await createTestApiToken("it-identity");
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", SHARED_IP).execute();
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(admin.id);
    await deleteTestApiToken(apiToken.id);
    await closeDb();
  });

  afterEach(async () => {
    await db.deleteFrom("scan_jobs").where("target_spec", "=", SHARED_IP).execute();
  });

  it("gives each scanner its own host row for the same ip, without merging or overwriting the other's data", async () => {
    const jobA = await createScanJob(agentA);
    await submitHost(agentA, jobA, 22);

    const jobB = await createScanJob(agentB);
    await submitHost(agentB, jobB, 3389);

    const client = await loginAs(admin.username, admin.password);
    const listRes = await client.get(`/api/hosts?q=${encodeURIComponent(SHARED_IP)}`);
    expect(listRes.status).toBe(200);

    const matches: HostRow[] = listRes.body.items;
    expect(matches).toHaveLength(2);
    expect(new Set(matches.map((m) => m.id)).size).toBe(2);

    const byAgent = new Map(matches.map((m) => [m.scanner_agent_name, m]));
    expect(byAgent.has(agentA.name)).toBe(true);
    expect(byAgent.has(agentB.name)).toBe(true);

    // Each host's own open ports must stay isolated - this is the actual
    // data-corruption the old global-unique-ip upsert would have caused.
    const hostA = await client.get(`/api/hosts/${byAgent.get(agentA.name)!.id}`);
    const hostB = await client.get(`/api/hosts/${byAgent.get(agentB.name)!.id}`);
    expect(hostA.body.ports.map((p: { port: number }) => p.port)).toEqual([22]);
    expect(hostB.body.ports.map((p: { port: number }) => p.port)).toEqual([3389]);
  });

  it("returns 409 with candidates from the external API when the ip is ambiguous across scanners", async () => {
    const jobA = await createScanJob(agentA);
    await submitHost(agentA, jobA, 22);
    const jobB = await createScanJob(agentB);
    await submitHost(agentB, jobB, 3389);

    const ambiguousRes = await request(getApp())
      .get(`/api/v1/hosts/lookup?ip=${SHARED_IP}`)
      .set("Authorization", `Bearer ${apiToken.token}`);
    expect(ambiguousRes.status).toBe(409);
    expect(ambiguousRes.body.candidates).toHaveLength(2);
    const names = ambiguousRes.body.candidates.map((c: { scannerAgentName: string }) => c.scannerAgentName);
    expect(new Set(names)).toEqual(new Set([agentA.name, agentB.name]));

    // scannerAgent disambiguates back down to a single, correct match.
    const disambiguatedRes = await request(getApp())
      .get(`/api/v1/hosts/lookup?ip=${SHARED_IP}&scannerAgent=${encodeURIComponent(agentA.name)}`)
      .set("Authorization", `Bearer ${apiToken.token}`);
    expect(disambiguatedRes.status).toBe(200);
    expect(disambiguatedRes.body.openPorts.map((p: { port: number }) => p.port)).toEqual([22]);
  });
});
