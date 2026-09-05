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
const CVE_IN_KEV = "CVE-1999-1003";

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
          { id: CVE_IN_KEV, description: "known exploited", cvssScore: 7.5, cvssSeverity: "HIGH", published: null },
        ]),
      })
      .execute();

    // Only CVE_WITH_EPSS gets a cached score - CVE_WITHOUT_EPSS is left
    // absent to exercise the left-join "sync hasn't caught up yet" case.
    await db.insertInto("epss_cache").values({ cve_id: CVE_WITH_EPSS, epss: 0.42, percentile: 0.91 }).execute();
    // Only CVE_IN_KEV is in the KEV catalog - the other two exercise the
    // left-join "most CVEs are never KEV-listed" case.
    await db
      .insertInto("kev_cache")
      .values({ cve_id: CVE_IN_KEV, vendor_project: "Test Vendor", product: "Test Product", vulnerability_name: "Test Vuln", date_added: "2024-01-15", known_ransomware_campaign_use: "Known" })
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("epss_cache").where("cve_id", "=", CVE_WITH_EPSS).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "=", CVE_IN_KEV).execute();
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

    const rows = res.body.items as Array<{ host_id: string; cve_id: string; epss_score: number | null; epss_percentile: number | null }>;
    const ours = rows.filter((r) => r.host_id === hostId);
    expect(ours).toHaveLength(3);

    const withScore = ours.find((r) => r.cve_id === CVE_WITH_EPSS);
    expect(withScore?.epss_score).toBeCloseTo(0.42);
    expect(withScore?.epss_percentile).toBeCloseTo(0.91);

    const withoutScore = ours.find((r) => r.cve_id === CVE_WITHOUT_EPSS);
    expect(withoutScore?.epss_score).toBeNull();
    expect(withoutScore?.epss_percentile).toBeNull();
  });

  it("joins the cached KEV entry onto a matching CVE (as a plain YYYY-MM-DD string, not a raw Date), leaves it null otherwise, and sorts KEV-listed rows first", async () => {
    const res = await adminClient.get("/api/vulnerabilities");
    expect(res.status).toBe(200);

    const rows = res.body.items as Array<{ host_id: string; cve_id: string; cvss_score: number | null; kev_date_added: string | null; kev_known_ransomware_campaign_use: string | null }>;
    const ours = rows.filter((r) => r.host_id === hostId);

    const kevRow = ours.find((r) => r.cve_id === CVE_IN_KEV);
    expect(kevRow?.kev_date_added).toBe("2024-01-15");
    expect(kevRow?.kev_known_ransomware_campaign_use).toBe("Known");

    const nonKevRow = ours.find((r) => r.cve_id === CVE_WITH_EPSS);
    expect(nonKevRow?.kev_date_added).toBeNull();

    // CVE_IN_KEV (cvssScore 7.5) must sort ahead of CVE_WITH_EPSS
    // (cvssScore 9.8, higher severity but not KEV-listed) - KEV
    // membership outranks raw CVSS score in the fleet-wide sort.
    const kevIndex = ours.findIndex((r) => r.cve_id === CVE_IN_KEV);
    const higherCvssIndex = ours.findIndex((r) => r.cve_id === CVE_WITH_EPSS);
    expect(kevIndex).toBeLessThan(higherCvssIndex);
  });

  it("also joins EPSS and KEV onto the per-host port detail's vulnerabilities list", async () => {
    const res = await adminClient.get(`/api/hosts/${hostId}`);
    expect(res.status).toBe(200);

    const port = (
      res.body.ports as Array<{
        port: number;
        vulnerabilities: Array<{ id: string; epssScore: number | null; epssPercentile: number | null; kevDateAdded: string | null; kevKnownRansomwareCampaignUse: string | null }>;
      }>
    ).find((p) => p.port === PORT);
    expect(port?.vulnerabilities).toHaveLength(3);

    const withScore = port?.vulnerabilities.find((v) => v.id === CVE_WITH_EPSS);
    expect(withScore?.epssScore).toBeCloseTo(0.42);
    expect(withScore?.epssPercentile).toBeCloseTo(0.91);
    expect(withScore?.kevDateAdded).toBeNull();

    const withoutScore = port?.vulnerabilities.find((v) => v.id === CVE_WITHOUT_EPSS);
    expect(withoutScore?.epssScore).toBeNull();

    const kevEntry = port?.vulnerabilities.find((v) => v.id === CVE_IN_KEV);
    expect(kevEntry?.kevDateAdded).toBe("2024-01-15");
    expect(kevEntry?.kevKnownRansomwareCampaignUse).toBe("Known");
  });
});
