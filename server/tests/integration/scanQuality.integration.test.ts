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

// 240.0.0.0/4 is reserved and never routable - the same fixture
// convention the other suites use, so this can never collide with real
// data.
const SUBNET = "240.21.0";
const ip = (last: number) => `${SUBNET}.${last}`;

async function startJob(agent: TestAgent, targetSpec: string, portSpec: string): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec, portSpec });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function ingest(agent: TestAgent, scanJobId: string, hosts: unknown[]): Promise<number> {
  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId, hosts });
  return res.status;
}

async function complete(agent: TestAgent, jobId: string, body: Record<string, unknown>): Promise<void> {
  const res = await request(getApp())
    .patch(`/api/ingest/scan-jobs/${jobId}`)
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send(body);
  expect(res.status).toBe(204);
}

describe("scan quality", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-scanquality-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    // closeDb only in the last describe of the file - it ends the shared
    // pg pool, which the suites after it still need.
  });

  // The defect this exists for: masscan reports a SYN-ACK, nmap confirms
  // nothing, the scanner submits the host with an empty port list, and a
  // permanent hosts row appeared anyway - 55% of one real fleet.
  it("does not create a host from a payload with no ports", async () => {
    const jobId = await startJob(agent, `${SUBNET}.0/24`, "53");
    expect(await ingest(agent, jobId, [{ ip: ip(10), ports: [] }])).toBe(204);

    const host = await db
      .selectFrom("hosts")
      .select(["id"])
      .where("ip", "=", ip(10))
      .where("scanner_agent_id", "=", agent.id)
      .executeTakeFirst();
    expect(host).toBeUndefined();
  });

  // The other half of that rule, and the one that makes it safe: a host
  // already known still goes through, because an empty payload for one of
  // those is what the port.closed inference reads.
  it("still updates a known host submitted with no ports, and closes its ports", async () => {
    const firstJob = await startJob(agent, ip(11), "22");
    expect(
      await ingest(agent, firstJob, [
        { ip: ip(11), ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] },
      ])
    ).toBe(204);

    const created = await db
      .selectFrom("hosts")
      .select(["id"])
      .where("ip", "=", ip(11))
      .where("scanner_agent_id", "=", agent.id)
      .executeTakeFirstOrThrow();

    const secondJob = await startJob(agent, ip(11), "22");
    expect(await ingest(agent, secondJob, [{ ip: ip(11), ports: [] }])).toBe(204);

    const stillThere = await db
      .selectFrom("hosts")
      .select(["id"])
      .where("id", "=", created.id)
      .executeTakeFirst();
    expect(stillThere).toBeDefined();

    const latest = await db
      .selectFrom("current_host_ports")
      .select(["state"])
      .where("host_id", "=", created.id)
      .where("port", "=", 22)
      .executeTakeFirstOrThrow();
    expect(latest.state).toBe("closed");
  });

  it("flags one service answering for a whole range", async () => {
    const jobId = await startJob(agent, `${SUBNET}.0/24`, "53");
    // 25 hosts, every one of them only :53 and only "Unbound" - the exact
    // shape a DNS interception produces, and indistinguishable per host.
    const hosts = Array.from({ length: 25 }, (_, i) => ({
      ip: ip(100 + i),
      ports: [
        { port: 53, protocol: "tcp", state: "open", serviceName: "domain", serviceProduct: "Unbound" },
      ],
    }));
    expect(await ingest(agent, jobId, hosts)).toBe(204);
    await complete(agent, jobId, { status: "completed", discoveredHosts: 25 });

    const job = await db.selectFrom("scan_jobs").select(["anomalies"]).where("id", "=", jobId).executeTakeFirstOrThrow();
    const anomalies = (job.anomalies ?? []) as Array<Record<string, unknown>>;
    const dominant = anomalies.find((a) => a.kind === "dominant_service");
    expect(dominant).toBeDefined();
    expect(dominant!.port).toBe(53);
    expect(dominant!.product).toBe("Unbound");
    expect(dominant!.hosts).toBe(25);
  });

  it("flags discovery finding far more than enrichment confirms", async () => {
    const jobId = await startJob(agent, `${SUBNET}.0/24`, "1-1024");
    // Three confirmed hosts, and each with a different service so the
    // dominant-service check cannot fire and confuse the assertion.
    expect(
      await ingest(agent, jobId, [
        { ip: ip(200), ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] },
        { ip: ip(201), ports: [{ port: 80, protocol: "tcp", state: "open", serviceName: "http" }] },
        { ip: ip(202), ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https" }] },
      ])
    ).toBe(204);
    await complete(agent, jobId, { status: "completed", discoveredHosts: 256 });

    const job = await db
      .selectFrom("scan_jobs")
      .select(["anomalies", "discovered_hosts"])
      .where("id", "=", jobId)
      .executeTakeFirstOrThrow();
    expect(job.discovered_hosts).toBe(256);
    const anomalies = (job.anomalies ?? []) as Array<Record<string, unknown>>;
    const unconfirmed = anomalies.find((a) => a.kind === "unconfirmed_discovery");
    expect(unconfirmed).toBeDefined();
    expect(unconfirmed!.discovered).toBe(256);
    expect(unconfirmed!.confirmed).toBe(3);
  });

  // A scanner too old to report the count must not produce a finding
  // about itself - absent is "unknown", not zero.
  it("reports no discovery anomaly when the scanner did not send a count", async () => {
    const jobId = await startJob(agent, ip(210), "22");
    expect(
      await ingest(agent, jobId, [{ ip: ip(210), ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] }])
    ).toBe(204);
    await complete(agent, jobId, { status: "completed" });

    const job = await db
      .selectFrom("scan_jobs")
      .select(["anomalies", "discovered_hosts"])
      .where("id", "=", jobId)
      .executeTakeFirstOrThrow();
    expect(job.discovered_hosts).toBeNull();
    expect((job.anomalies ?? []) as unknown[]).toEqual([]);
  });

  it("does not run the checks on a cancelled scan", async () => {
    const jobId = await startJob(agent, `${SUBNET}.0/24`, "53");
    await complete(agent, jobId, { status: "cancelled", discoveredHosts: 999 });
    const job = await db.selectFrom("scan_jobs").select(["anomalies"]).where("id", "=", jobId).executeTakeFirstOrThrow();
    expect(job.anomalies).toBeNull();
  });

  it("exposes the scan-quality fields through the history endpoint", async () => {
    const res = await client.get("/api/scan-jobs/history?pageSize=200");
    expect(res.status).toBe(200);
    const mine = res.body.items.filter((i: { scanner_agent_name: string }) => i.scanner_agent_name === agent.name);
    expect(mine.length).toBeGreaterThan(0);
    const withDiscovery = mine.find(
      (i: { discovered_hosts: number | null; status: string }) => i.discovered_hosts === 256 && i.status === "completed"
    );
    expect(withDiscovery).toBeDefined();
    expect(Array.isArray(withDiscovery.anomalies)).toBe(true);
  });
});

describe("scanner coverage overlap", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let admin: TestUser;
  let client: SessionClient;
  const sharedIp = "240.22.0.5";
  const uniqueIp = "240.22.0.6";

  beforeAll(async () => {
    agentA = await createTestAgent("it-overlap-a");
    agentB = await createTestAgent("it-overlap-b");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);

    for (const [agent, ips] of [
      [agentA, [sharedIp, uniqueIp]],
      [agentB, [sharedIp]],
    ] as Array<[TestAgent, string[]]>) {
      const jobId = await startJob(agent, "240.22.0.0/24", "22");
      await ingest(
        agent,
        jobId,
        ips.map((addr) => ({ ip: addr, ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] }))
      );
    }
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("scanner_agent_id", "in", [agentA.id, agentB.id]).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agentA.id, agentB.id]).execute();
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  // Host identity is (ip, scanner_agent_id), so this is correct storage -
  // what was missing is anyone saying it happened.
  it("reports an address covered by two scanners", async () => {
    const res = await client.get("/api/hosts/overlap");
    expect(res.status).toBe(200);
    expect(res.body.hostRows).toBeGreaterThan(res.body.distinctAddresses);

    const duplicate = res.body.duplicates.find((d: { ip: string }) => d.ip === sharedIp);
    expect(duplicate).toBeDefined();
    expect(duplicate.scanners).toContain(agentA.name);
    expect(duplicate.scanners).toContain(agentB.name);

    // An address only one scanner has must not be listed - the whole
    // value of the number is that it counts real duplication.
    expect(res.body.duplicates.some((d: { ip: string }) => d.ip === uniqueIp)).toBe(false);
  });
});
