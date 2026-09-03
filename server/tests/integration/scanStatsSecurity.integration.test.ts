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

// Class E again, and its own /24 so this file's fixtures can't collide
// with scanStats.integration.test.ts running before or after it.
const NET = "240.31.0.0/24";
const IP_A = "240.31.0.1";
const IP_B = "240.31.0.2";
const CPE = "cpe:/a:porttorch:stats-test:1.0";
const CRIT_CVE = "CVE-1999-8801";
const HIGH_CVE = "CVE-1999-8802";
const NOSCORE_CVE = "CVE-1999-8803";

interface Slice {
  label: string;
  value: number;
}

interface SecurityBody {
  totals: {
    cveFindings: number;
    affectedHosts: number;
    kevFindings: number;
    kevHosts: number;
    ransomwareCves: number;
    webFindings: number;
  };
  cveSeverities: Slice[];
  epssBuckets: Slice[];
  nucleiSeverities: Slice[];
  topHosts: Array<{
    hostId: string;
    ip: string;
    cveCount: number;
    maxCvss: number | null;
    kevCount: number;
    webFindings: number;
  }>;
}

function sliceValue(slices: Slice[], label: string): number {
  return slices.find((s) => s.label === label)?.value ?? 0;
}

describe("scan stats security", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;
  let hostA: string;
  let hostB: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-stats-sec");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: NET, portSpec: "443,8443" });
    expect(jobRes.status).toBe(201);

    const hostsRes = await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            // The same CPE on two ports of one host - the case that
            // decides whether a finding is counted per host or per port.
            ip: IP_A,
            ports: [
              { port: 443, protocol: "tcp", state: "open", serviceName: "https", cpes: [CPE] },
              { port: 8443, protocol: "tcp", state: "open", serviceName: "https-alt", cpes: [CPE] },
            ],
          },
          { ip: IP_B, ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https", cpes: [CPE] }] },
        ],
      });
    expect(hostsRes.status).toBe(204);

    hostA = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow()).id;
    hostB = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_B).executeTakeFirstOrThrow()).id;

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: CRIT_CVE, cvssScore: 9.8, cvssSeverity: "CRITICAL", description: "critical one" },
          { id: HIGH_CVE, cvssScore: 7.5, cvssSeverity: "HIGH", description: "high one" },
          // No CVSS metric at all - NVD publishes plenty of these.
          { id: NOSCORE_CVE, description: "unscored one" },
        ]),
      })
      .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: (eb) => eb.ref("excluded.cves") }))
      .execute();

    await db
      .insertInto("epss_cache")
      .values([
        { cve_id: CRIT_CVE, epss: 0.87, percentile: 0.99 },
        { cve_id: HIGH_CVE, epss: 0.02, percentile: 0.5 },
      ])
      .onConflict((oc) => oc.column("cve_id").doUpdateSet({ epss: (eb) => eb.ref("excluded.epss") }))
      .execute();

    await db
      .insertInto("kev_cache")
      .values({
        cve_id: CRIT_CVE,
        vendor_project: "PortTorch",
        product: "stats-test",
        vulnerability_name: "critical one",
        date_added: "2024-01-01",
        known_ransomware_campaign_use: "Known",
      })
      .onConflict((oc) => oc.column("cve_id").doNothing())
      .execute();

    await db
      .insertInto("nuclei_findings")
      .values([
        { host_id: hostA, scan_job_id: jobRes.body.id, port: 443, template_id: "it-stats-exposed-env", name: "env", severity: "high", matched_at: "https://a/.env" },
        // Same finding observed twice - a rescan must not double it.
        { host_id: hostA, scan_job_id: jobRes.body.id, port: 443, template_id: "it-stats-exposed-env", name: "env", severity: "high", matched_at: "https://a/.env" },
        { host_id: hostB, scan_job_id: jobRes.body.id, port: 443, template_id: "it-stats-tech-detect", name: "tech", severity: "info", matched_at: "https://b/" },
      ])
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("nuclei_findings").where("template_id", "like", "it-stats-%").execute();
    await db.deleteFrom("finding_triage").where("host_id", "in", [hostA, hostB]).execute();
    await db.deleteFrom("finding_triage_rules").where("cve_id", "=", HIGH_CVE).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("epss_cache").where("cve_id", "in", [CRIT_CVE, HIGH_CVE]).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "=", CRIT_CVE).execute();
    await sql`DELETE FROM hosts WHERE ip <<= ${NET}::cidr`.execute(db);
    await db.deleteFrom("scan_jobs").where("target_spec", "=", NET).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function security(): Promise<SecurityBody> {
    const res = await client.get(`/api/scan-stats/security?scannerAgentId=${agent.id}`);
    expect(res.status).toBe(200);
    return res.body as SecurityBody;
  }

  it("counts a finding once per host and CVE, not once per port", async () => {
    const body = await security();
    // Two hosts x three CVEs. Host A has the same CPE on two ports, which
    // would make this 9 if ports were counted.
    expect(body.totals.cveFindings).toBe(6);
    expect(body.totals.affectedHosts).toBe(2);
    expect(sliceValue(body.cveSeverities, "Critical")).toBe(2);
    expect(sliceValue(body.cveSeverities, "High")).toBe(2);
    // A CVE with no CVSS metric is its own slice rather than being
    // dropped, so the chart still sums to the finding total.
    expect(sliceValue(body.cveSeverities, "Unknown")).toBe(2);
    expect(body.cveSeverities.reduce((sum, s) => sum + s.value, 0)).toBe(body.totals.cveFindings);
  });

  it("buckets EPSS scores and reports KEV and ransomware separately", async () => {
    const body = await security();
    expect(sliceValue(body.epssBuckets, "≥ 50%")).toBe(2); // the critical one, on both hosts
    expect(sliceValue(body.epssBuckets, "1-10%")).toBe(2);
    expect(sliceValue(body.epssBuckets, "No score yet")).toBe(2);
    expect(body.epssBuckets.reduce((sum, s) => sum + s.value, 0)).toBe(body.totals.cveFindings);

    expect(body.totals.kevFindings).toBe(2);
    expect(body.totals.kevHosts).toBe(2);
    // Counted as distinct CVEs, not per host - it is one vulnerability
    // known to be used by ransomware, seen twice.
    expect(body.totals.ransomwareCves).toBe(1);
  });

  it("dedups repeated nuclei observations of the same finding", async () => {
    const body = await security();
    expect(body.totals.webFindings).toBe(2);
    expect(sliceValue(body.nucleiSeverities, "High")).toBe(1);
    expect(sliceValue(body.nucleiSeverities, "Info")).toBe(1);
  });

  it("ranks the most exposed hosts the way the Vulnerabilities page does", async () => {
    const body = await security();
    expect(body.topHosts).toHaveLength(2);
    const a = body.topHosts.find((h) => h.hostId === hostA);
    expect(a).toMatchObject({ cveCount: 3, kevCount: 1, maxCvss: 9.8, webFindings: 1 });
  });

  it("leaves out findings triaged as not a live risk, per host and fleet-wide", async () => {
    const before = await security();
    expect(before.totals.cveFindings).toBe(6);

    // Per-host: a false positive on host A only.
    await db
      .insertInto("finding_triage")
      .values({ kind: "cve", host_id: hostA, cve_id: CRIT_CVE, state: "false_positive", created_by: admin.username })
      .execute();
    const afterHost = await security();
    expect(afterHost.totals.cveFindings).toBe(5);
    expect(afterHost.totals.kevFindings).toBe(1); // still open on host B
    expect(sliceValue(afterHost.cveSeverities, "Critical")).toBe(1);

    // An accepted risk is still exposure and must keep counting - the one
    // place this policy differs from alerting.
    await db
      .insertInto("finding_triage")
      .values({ kind: "cve", host_id: hostB, cve_id: HIGH_CVE, state: "accepted_risk", created_by: admin.username })
      .execute();
    expect((await security()).totals.cveFindings).toBe(5);

    // Fleet-wide rule: drops the high CVE from both hosts at once.
    await db
      .insertInto("finding_triage_rules")
      .values({ kind: "cve", cve_id: HIGH_CVE, state: "fixed", created_by: admin.username })
      .execute();
    const afterRule = await security();
    expect(afterRule.totals.cveFindings).toBe(3);
    expect(sliceValue(afterRule.cveSeverities, "High")).toBe(0);
  });
});
