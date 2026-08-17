import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target, so it can't
// collide with genuine data when this suite runs against a copy of a
// real database.
const IP = "240.5.6.7";

async function createScanJob(agent: TestAgent): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: IP, portSpec: "22,80,3306" });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function submitHost(agent: TestAgent, scanJobId: string, ports: Array<{ port: number; protocol?: string; state?: string; serviceName?: string }>) {
  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId, hosts: [{ ip: IP, ports }] });
  expect(res.status).toBe(204);
}

async function hostIdFor(agent: TestAgent): Promise<string> {
  const row = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", IP)
    .where("scanner_agent_id", "=", agent.id)
    .executeTakeFirstOrThrow();
  return row.id;
}

async function tagsFor(hostId: string): Promise<string[]> {
  const rows = await db.selectFrom("host_tags").select(["tag"]).where("host_id", "=", hostId).orderBy("tag").execute();
  return rows.map((r) => r.tag);
}

// Auto-tagging is generic, service-derived (server/src/lib/serviceTags.ts
// has the unit-tested rule table) - this integration test only needs to
// confirm the ingest path actually wires that derivation into host_tags,
// and that the "never auto-removed, but idempotent" design decision
// documented in CLAUDE.md actually holds against a real ingest sequence.
describe("service-derived auto-tags on ingest", () => {
  let agent: TestAgent;

  beforeAll(async () => {
    agent = await createTestAgent("it-auto-tags-agent");
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  afterEach(async () => {
    await db.deleteFrom("scan_jobs").where("target_spec", "=", IP).execute();
  });

  it("adds tags for every recognized open service found on the host", async () => {
    const jobId = await createScanJob(agent);
    await submitHost(agent, jobId, [
      { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
      { port: 80, protocol: "tcp", state: "open", serviceName: "http" },
      { port: 3306, protocol: "tcp", state: "open", serviceName: "mysql" },
    ]);

    const hostId = await hostIdFor(agent);
    expect(await tagsFor(hostId)).toEqual(["MySQL", "SSH-Server", "WebServer"]);
  });

  it("re-ingesting the same open ports again does not error or duplicate the tags", async () => {
    const jobId = await createScanJob(agent);
    await submitHost(agent, jobId, [
      { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
      { port: 80, protocol: "tcp", state: "open", serviceName: "http" },
      { port: 3306, protocol: "tcp", state: "open", serviceName: "mysql" },
    ]);

    const hostId = await hostIdFor(agent);
    expect(await tagsFor(hostId)).toEqual(["MySQL", "SSH-Server", "WebServer"]);
  });

  it("a manually removed auto-tag comes back on a later scan that still finds the same service", async () => {
    const hostId = await hostIdFor(agent);
    await db.deleteFrom("host_tags").where("host_id", "=", hostId).where("tag", "=", "SSH-Server").execute();
    expect(await tagsFor(hostId)).toEqual(["MySQL", "WebServer"]);

    const jobId = await createScanJob(agent);
    await submitHost(agent, jobId, [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);

    expect(await tagsFor(hostId)).toEqual(["MySQL", "SSH-Server", "WebServer"]);
  });

  it("does not tag a closed port even if the service name would otherwise match", async () => {
    await db.deleteFrom("host_tags").where("host_id", "=", await hostIdFor(agent)).execute();

    const jobId = await createScanJob(agent);
    await submitHost(agent, jobId, [{ port: 21, protocol: "tcp", state: "closed", serviceName: "ftp" }]);

    const hostId = await hostIdFor(agent);
    expect(await tagsFor(hostId)).toEqual([]);
  });
});
