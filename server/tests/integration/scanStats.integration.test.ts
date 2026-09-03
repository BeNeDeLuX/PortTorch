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
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

// Class E (240.0.0.0/4) - reserved, so nothing here collides with real
// data if the suite runs against a copy of a production database. Same
// convention as networkCoverage.integration.test.ts.
const NET = "240.30.0.0/24";

interface Slice {
  label: string;
  value: number;
}

interface StatsBody {
  hideRetired: boolean;
  totals: {
    hosts: number;
    openPorts: number;
    distinctPorts: number;
    distinctServices: number;
    certificates: number;
    selfSigned: number;
    expiringSoon: number;
  };
  comparison: { days: number; since: string; hosts: number; openPorts: number; certificates: number } | null;
  perScanner: Array<{ id: string | null; name: string; hosts: number; openPorts: number; certificates: number }>;
  osFamilies: Slice[];
  deviceTypes: Slice[];
  tags: Slice[];
  performanceWindowDays: number;
  scanPerformance: Array<{
    id: string | null;
    name: string;
    scans: number;
    completed: number;
    failed: number;
    cancelled: number;
    medianDurationMs: number | null;
  }>;
  topHostsByPorts: Array<{ hostId: string; ip: string; openPorts: number }>;
  topSubnets: Array<{ subnet: string; hosts: number; openPorts: number }>;
  topPorts: Slice[];
  portCategories: Slice[];
  protocols: Slice[];
  services: Slice[];
  certIssuance: Slice[];
  certExpiry: Slice[];
  tlsVersions: Slice[];
  certKeys: Slice[];
}

function sliceValue(slices: Slice[], label: string): number {
  return slices.find((s) => s.label === label)?.value ?? 0;
}

async function startJob(agent: TestAgent, targetSpec: string): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec, portSpec: "1-65535" });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

async function completeJob(agent: TestAgent, jobId: string): Promise<void> {
  const res = await request(getApp())
    .patch(`/api/ingest/scan-jobs/${jobId}`)
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ status: "completed" });
  expect(res.status).toBe(204);
}

describe("scan stats", () => {
  let agentA: TestAgent;
  let agentB: TestAgent;
  let admin: TestUser;
  let adminClient: SessionClient;

  beforeAll(async () => {
    agentA = await createTestAgent("it-stats-a");
    agentB = await createTestAgent("it-stats-b");
    admin = await createTestUser("admin");
    adminClient = await loginAs(admin.username, admin.password);

    const jobA = await startJob(agentA, "240.30.0.0/24");
    const hostsA = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agentA.apiKey}`)
      .send({
        scanJobId: jobA,
        hosts: [
          {
            ip: "240.30.0.1",
            ports: [
              { port: 443, protocol: "tcp", state: "open", serviceName: "https" },
              { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
              { port: 53, protocol: "udp", state: "open", serviceName: "domain" },
              // Closed ports are current state too, and must not be
              // counted anywhere on this page.
              { port: 3306, protocol: "tcp", state: "closed", serviceName: "mysql" },
            ],
          },
          {
            ip: "240.30.0.2",
            ports: [
              { port: 443, protocol: "tcp", state: "open", serviceName: "https" },
              // No service name at all - has to land in the "unknown"
              // slice rather than being dropped from the totals.
              { port: 49152, protocol: "tcp", state: "open" },
            ],
          },
        ],
      });
    expect(hostsA.status).toBe(204);

    // Two certificates for the same host+port from two different scans -
    // only the newer one may be counted, otherwise the page reports
    // observations instead of certificates.
    for (const [fingerprint, notAfter] of [
      ["it-stats-old-fingerprint", new Date(Date.now() + 400 * 864e5).toISOString()],
      ["it-stats-new-fingerprint", new Date(Date.now() + 10 * 864e5).toISOString()],
    ]) {
      const res = await request(getApp())
        .post("/api/ingest/tls-certificates")
        .set("Authorization", `Bearer ${agentA.apiKey}`)
        .send({
          scanJobId: jobA,
          hostIp: "240.30.0.1",
          port: 443,
          fingerprintSha256: fingerprint,
          selfSigned: true,
          tlsVersion: "TLSv1.3",
          keyAlgorithm: "RSA",
          keyBits: 2048,
          notAfter,
        });
      expect(res.status).toBe(201);
    }

    const certB = await request(getApp())
      .post("/api/ingest/tls-certificates")
      .set("Authorization", `Bearer ${agentA.apiKey}`)
      .send({
        scanJobId: jobA,
        hostIp: "240.30.0.2",
        port: 443,
        fingerprintSha256: "it-stats-ca-fingerprint",
        selfSigned: false,
        tlsVersion: "TLSv1.2",
        keyAlgorithm: "EC",
        keyBits: 256,
        notAfter: new Date(Date.now() + 200 * 864e5).toISOString(),
      });
    expect(certB.status).toBe(201);

    // Finished, so it counts toward the scan-performance figures - those
    // deliberately ignore a job still running, which has no duration yet.
    await completeJob(agentA, jobA);

    // A second scanner with one host, so the per-scanner breakdown and
    // the scanner filter have something to actually separate.
    const jobB = await startJob(agentB, "240.30.0.0/24");
    const hostsB = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agentB.apiKey}`)
      .send({
        scanJobId: jobB,
        hosts: [{ ip: "240.30.0.9", ports: [{ port: 3389, protocol: "tcp", state: "open", serviceName: "ms-wbt-server" }] }],
      });
    expect(hostsB.status).toBe(204);
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip <<= ${NET}::cidr`.execute(db);
    await db.deleteFrom("scan_jobs").where("target_spec", "=", "240.30.0.0/24").execute();
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function stats(query = ""): Promise<StatsBody> {
    const res = await adminClient.get(`/api/scan-stats${query}`);
    expect(res.status).toBe(200);
    return res.body as StatsBody;
  }

  it("counts only currently-open ports, per scanner", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);

    expect(body.totals.hosts).toBe(2);
    // 443, 22, 53/udp on .1 plus 443, 49152 on .2 - the closed 3306 is
    // deliberately not among them.
    expect(body.totals.openPorts).toBe(5);
    expect(sliceValue(body.topPorts, "443/tcp")).toBe(2);
    expect(sliceValue(body.topPorts, "22/tcp")).toBe(1);
    expect(body.topPorts.some((s) => s.label === "3306/tcp")).toBe(false);
    expect(sliceValue(body.protocols, "TCP")).toBe(4);
    expect(sliceValue(body.protocols, "UDP")).toBe(1);
  });

  it("groups ports into categories and keeps unfingerprinted ones visible", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);

    expect(sliceValue(body.portCategories, "Web")).toBe(2); // 443 twice
    expect(sliceValue(body.portCategories, "Remote access")).toBe(1); // 22
    expect(sliceValue(body.portCategories, "Network infrastructure")).toBe(1); // 53/udp
    expect(sliceValue(body.portCategories, "Other")).toBe(1); // 49152

    expect(sliceValue(body.services, "https")).toBe(2);
    expect(sliceValue(body.services, "unknown")).toBe(1);
    // Every chart on the page has to add up to the same total, which is
    // exactly what folding "unknown" in instead of dropping it buys.
    const sum = (slices: Slice[]) => slices.reduce((a, s) => a + s.value, 0);
    expect(sum(body.services)).toBe(body.totals.openPorts);
    expect(sum(body.portCategories)).toBe(body.totals.openPorts);
    expect(sum(body.protocols)).toBe(body.totals.openPorts);
  });

  it("counts the newest certificate per host and port, not every observation", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);

    expect(body.totals.certificates).toBe(2);
    expect(body.totals.selfSigned).toBe(1);
    expect(sliceValue(body.certIssuance, "Self-signed")).toBe(1);
    expect(sliceValue(body.certIssuance, "CA-issued")).toBe(1);
    // The newer of the two certificates on .1:443 expires in 10 days, the
    // older one in 400 - if the older one were the one being counted this
    // bucket would be empty.
    expect(sliceValue(body.certExpiry, "≤ 30 days")).toBe(1);
    expect(body.totals.expiringSoon).toBe(1);
    expect(sliceValue(body.tlsVersions, "TLSv1.3")).toBe(1);
    expect(sliceValue(body.certKeys, "RSA 2048")).toBe(1);
    expect(sliceValue(body.certKeys, "EC 256")).toBe(1);
  });

  it("breaks the fleet down per scanner and narrows on the scanner filter", async () => {
    const both = await stats(`?scannerAgentId=${agentA.id},${agentB.id}`);
    const a = both.perScanner.find((s) => s.id === agentA.id);
    const b = both.perScanner.find((s) => s.id === agentB.id);

    expect(a).toMatchObject({ hosts: 2, openPorts: 5, certificates: 2 });
    expect(b).toMatchObject({ hosts: 1, openPorts: 1, certificates: 0 });
    expect(both.totals.hosts).toBe(3);
    expect(both.totals.openPorts).toBe(6);

    const onlyB = await stats(`?scannerAgentId=${agentB.id}`);
    expect(onlyB.totals.hosts).toBe(1);
    expect(onlyB.perScanner).toHaveLength(1);
    expect(sliceValue(onlyB.portCategories, "Remote access")).toBe(1);
  });

  it("reports an unclassified fleet as such rather than as an empty chart", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);

    // Nothing in these fixtures carries OS data (nmap only fingerprints
    // for real root - see the scanner's nmapSudo), so every host lands in
    // one honest slice instead of the charts coming back empty.
    expect(sliceValue(body.osFamilies, "Not classified")).toBe(2);
    expect(sliceValue(body.deviceTypes, "Not classified")).toBe(2);
    expect(body.osFamilies.reduce((sum, s) => sum + s.value, 0)).toBe(body.totals.hosts);

    // Tags come from the ingest path's own service auto-tags. Unlike the
    // charts above they do not partition the fleet - a host carries as
    // many as apply - so this deliberately doesn't sum to the host count.
    expect(sliceValue(body.tags, "WebServer")).toBe(2);
    expect(sliceValue(body.tags, "SSH-Server")).toBe(1);
  });

  it("ranks hosts and subnets by open ports", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);

    expect(body.topHostsByPorts[0]).toMatchObject({ ip: "240.30.0.1", openPorts: 3 });
    expect(body.topHostsByPorts[1]).toMatchObject({ ip: "240.30.0.2", openPorts: 2 });

    // Both fixture hosts sit in the same /24, so they collapse into one
    // subnet row carrying every open port between them.
    expect(body.topSubnets).toHaveLength(1);
    expect(body.topSubnets[0]).toMatchObject({ subnet: "240.30.0.0/24", hosts: 2, openPorts: 5 });
  });

  it("reports scan performance per scanner over its own window", async () => {
    const body = await stats(`?scannerAgentId=${agentA.id}`);
    expect(body.performanceWindowDays).toBe(30);

    const perf = body.scanPerformance.find((p) => p.id === agentA.id);
    expect(perf).toBeDefined();
    expect(perf!.scans).toBe(1);
    expect(perf!.completed).toBe(1);
    expect(perf!.failed).toBe(0);
    // A finished job always has a duration, even if it is near zero.
    expect(perf!.medianDurationMs).not.toBeNull();
  });

  it("computes the comparison only when asked, and reconstructs the same measurement", async () => {
    const withoutIt = await stats(`?scannerAgentId=${agentA.id}`);
    expect(withoutIt.comparison).toBeNull();

    const withIt = await stats(`?scannerAgentId=${agentA.id}&compareDays=7`);
    expect(withIt.comparison).not.toBeNull();
    expect(withIt.comparison!.days).toBe(7);
    // Everything here was created seconds ago, so as of a week back this
    // fleet did not exist - the whole current count is the change.
    expect(withIt.comparison!.hosts).toBe(0);
    expect(withIt.comparison!.openPorts).toBe(0);
    expect(withIt.comparison!.certificates).toBe(0);

    // An unsupported window is ignored rather than honoured, so a crafted
    // value can't turn one page load into an unbounded scan of the
    // append-only observations table.
    const bogus = await stats(`?scannerAgentId=${agentA.id}&compareDays=4000`);
    expect(bogus.comparison).toBeNull();
  });

  it("includes retired hosts by default and drops them on request", async () => {
    await db
      .updateTable("hosts")
      .set({ retired_at: new Date().toISOString() })
      .where("ip", "=", "240.30.0.2")
      .execute();

    const included = await stats(`?scannerAgentId=${agentA.id}`);
    expect(included.hideRetired).toBe(false);
    expect(included.totals.hosts).toBe(2);

    const hidden = await stats(`?scannerAgentId=${agentA.id}&hideRetired=1`);
    expect(hidden.hideRetired).toBe(true);
    expect(hidden.totals.hosts).toBe(1);
    expect(hidden.totals.openPorts).toBe(3);
    expect(hidden.totals.certificates).toBe(1);

    await db.updateTable("hosts").set({ retired_at: null }).where("ip", "=", "240.30.0.2").execute();
  });

  it("never shows a restricted session data from a scanner it is not assigned to", async () => {
    const restricted = await createTestUser("operator");
    try {
      await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: agentB.id }).execute();
      const restrictedClient = await loginAs(restricted.username, restricted.password);
      const res = await restrictedClient.get(`/api/scan-stats?scannerAgentId=${agentA.id},${agentB.id}`);
      expect(res.status).toBe(200);
      const body = res.body as StatsBody;
      // Asked for both scanners, allowed only one - the filter can narrow
      // but never widen past the assignment.
      expect(body.perScanner.map((s) => s.id)).toEqual([agentB.id]);
      expect(body.totals.hosts).toBe(1);
      expect(body.totals.certificates).toBe(0);
    } finally {
      await deleteTestUser(restricted.id);
    }
  });
});
