import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.6.2.1";
const PORT = 443;
// Fake, never-real CPE/CVE ids so these rows can't collide with anything a
// real NVD/EPSS sync would ever cache.
const CPE = "cpe:/a:porttorch-test:vuln-epss:1.0";
const CVE_WITH_EPSS = "CVE-1999-1001";
const CVE_WITHOUT_EPSS = "CVE-1999-1002";

describe("GET /api/vulnerabilities", () => {
  let admin: TestUser;
  let adminClient: SessionClient;
  let agent: TestAgent;
  let hostId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-vuln-agent");
    admin = await createTestUser("admin");
    adminClient = await loginAs(admin.username, admin.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: String(PORT) });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: jobRes.body.id, hosts: [{ ip: IP, ports: [{ port: PORT, protocol: "tcp", state: "open", cpes: [CPE] }] }] });

    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow();
    hostId = host.id;

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: CVE_WITH_EPSS, description: "has an epss score", cvssScore: 9.8, cvssSeverity: "CRITICAL", published: null },
          { id: CVE_WITHOUT_EPSS, description: "no epss score yet", cvssScore: 5.0, cvssSeverity: "MEDIUM", published: null },
        ]),
      })
      .execute();

    // Only CVE_WITH_EPSS gets a cached score - CVE_WITHOUT_EPSS is left
    // absent to exercise the left-join "sync hasn't caught up yet" case.
    await db.insertInto("epss_cache").values({ cve_id: CVE_WITH_EPSS, epss: 0.42, percentile: 0.91 }).execute();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("epss_cache").where("cve_id", "=", CVE_WITH_EPSS).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("requires authentication", async () => {
    const res = await request(getApp()).get("/api/vulnerabilities");
    expect(res.status).toBe(401);
  });

  it("joins the cached EPSS score onto a matching CVE, and leaves it null when no score is cached yet", async () => {
    const res = await adminClient.get("/api/vulnerabilities");
    expect(res.status).toBe(200);

    const rows = res.body as Array<{ host_id: string; cve_id: string; epss_score: number | null; epss_percentile: number | null }>;
    const ours = rows.filter((r) => r.host_id === hostId);
    expect(ours).toHaveLength(2);

    const withScore = ours.find((r) => r.cve_id === CVE_WITH_EPSS);
    expect(withScore?.epss_score).toBeCloseTo(0.42);
    expect(withScore?.epss_percentile).toBeCloseTo(0.91);

    const withoutScore = ours.find((r) => r.cve_id === CVE_WITHOUT_EPSS);
    expect(withoutScore?.epss_score).toBeNull();
    expect(withoutScore?.epss_percentile).toBeNull();
  });

  it("also joins EPSS onto the per-host port detail's vulnerabilities list", async () => {
    const res = await adminClient.get(`/api/hosts/${hostId}`);
    expect(res.status).toBe(200);

    const port = (res.body.ports as Array<{ port: number; vulnerabilities: Array<{ id: string; epssScore: number | null; epssPercentile: number | null }> }>).find(
      (p) => p.port === PORT
    );
    expect(port?.vulnerabilities).toHaveLength(2);

    const withScore = port?.vulnerabilities.find((v) => v.id === CVE_WITH_EPSS);
    expect(withScore?.epssScore).toBeCloseTo(0.42);
    expect(withScore?.epssPercentile).toBeCloseTo(0.91);

    const withoutScore = port?.vulnerabilities.find((v) => v.id === CVE_WITHOUT_EPSS);
    expect(withoutScore?.epssScore).toBeNull();
  });
});
