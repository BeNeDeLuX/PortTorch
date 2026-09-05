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

const IP = "240.12.1.1";
const CPE = "cpe:/a:it-triage-consistency:widget:1.0";
const FP_CVE = "CVE-1999-9001";
const ACCEPTED_CVE = "CVE-1999-9002";
const OPEN_CVE = "CVE-1999-9003";

// Triage has to mean the same thing everywhere it's consulted, but "the
// same thing" is not "hide it" on every surface - see
// findingTriage/sqlFilters.ts. These tests pin the three different
// answers down so they can't quietly drift apart again.
describe("triage is respected consistently across surfaces", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let client: SessionClient;
  let hostId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-triage-consistency-agent");
    operator = await createTestUser("operator");
    client = await loginAs(operator.username, operator.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "443" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [{ ip: IP, ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https", cpes: [CPE] }] }],
      });

    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow();
    hostId = host.id;

    // Three CVEs on one CPE: one will be a false positive, one an accepted
    // risk, one left untriaged as the control.
    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: FP_CVE, cvssScore: 9.8, cvssSeverity: "CRITICAL", description: "false positive one" },
          { id: ACCEPTED_CVE, cvssScore: 8.1, cvssSeverity: "HIGH", description: "accepted risk one" },
          { id: OPEN_CVE, cvssScore: 5.0, cvssSeverity: "MEDIUM", description: "untriaged one" },
        ]),
      })
      .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: (eb) => eb.ref("excluded.cves") }))
      .execute();

    // Every one of them is in the KEV catalog, so has_kev would be true
    // if triage were ignored.
    for (const cveId of [FP_CVE, ACCEPTED_CVE, OPEN_CVE]) {
      await db
        .insertInto("kev_cache")
        .values({ cve_id: cveId, date_added: "1999-01-01", known_ransomware_campaign_use: "Unknown" })
        .onConflict((oc) => oc.column("cve_id").doNothing())
        .execute();
    }

    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: FP_CVE, state: "false_positive" });
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: ACCEPTED_CVE, state: "accepted_risk" });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "in", [FP_CVE, ACCEPTED_CVE, OPEN_CVE]).execute();
    await deleteTestUser(operator.id);
    await deleteTestAgent(agent.id);
  });

  it("drops a false positive from the host list risk indicator, but keeps an accepted risk", async () => {
    const res = await client.get(`/api/hosts?q=${IP}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host).toBeDefined();

    // Untriaged (5.0) + accepted risk (8.1) count; the 9.8 false positive
    // does not - so both the count and the max score reflect that.
    expect(host.cve_count).toBe(2);
    expect(host.max_cvss_score).toBe(8.1);
  });

  it("still flags KEV when a non-false-positive KEV CVE remains", async () => {
    const res = await client.get(`/api/hosts?q=${IP}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host.has_kev).toBe(true);
  });

  it("clears the KEV flag once every KEV CVE on the host is a false positive or fixed", async () => {
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: ACCEPTED_CVE, state: "fixed" });
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: OPEN_CVE, state: "false_positive" });

    const res = await client.get(`/api/hosts?q=${IP}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host.cve_count).toBe(0);
    expect(host.has_kev).toBe(false);

    // Put the fixture back for the remaining tests.
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: ACCEPTED_CVE, state: "accepted_risk" });
    await client.delete("/api/finding-triage").send({ kind: "cve", hostId, cveId: OPEN_CVE });
  });

  it("keeps every CVE listed on host detail - the full record - but marks the triaged ones", async () => {
    const res = await client.get(`/api/hosts/${hostId}`);
    const port = res.body.ports.find((p: { port: number }) => p.port === 443);
    const byId = new Map(port.vulnerabilities.map((v: { id: string }) => [v.id, v]));

    // Nothing is hidden here, unlike the fleet-wide page.
    expect(byId.size).toBe(3);
    expect((byId.get(FP_CVE) as { triageState: string }).triageState).toBe("false_positive");
    expect((byId.get(ACCEPTED_CVE) as { triageState: string }).triageState).toBe("accepted_risk");
    expect((byId.get(OPEN_CVE) as { triageState: string | null }).triageState).toBeNull();
  });

  it("hides triaged CVEs from the fleet-wide Vulnerabilities list by default", async () => {
    const res = await client.get("/api/vulnerabilities");
    const forHost = res.body.items.filter((v: { host_id: string }) => v.host_id === hostId);
    const states = new Map(forHost.map((v: { cve_id: string; triage_state: string | null }) => [v.cve_id, v.triage_state]));

    // The route returns all of them with their state attached - the page
    // does the hiding - so this asserts the state is actually joined in.
    expect(states.get(FP_CVE)).toBe("false_positive");
    expect(states.get(ACCEPTED_CVE)).toBe("accepted_risk");
    expect(states.get(OPEN_CVE)).toBeNull();
  });
});

// An expiring decision is the whole reason review_at exists: accepting a
// risk forever quietly recreates the problem triage was built to solve.
describe("an expired triage decision stops being honored everywhere", () => {
  let agent: TestAgent;
  let operator: TestUser;
  let client: SessionClient;
  let hostId: string;
  const IP2 = "240.12.2.2";
  const CPE2 = "cpe:/a:it-triage-expiry:widget:1.0";
  const CVE2 = "CVE-1999-9101";

  beforeAll(async () => {
    agent = await createTestAgent("it-triage-expiry-agent");
    operator = await createTestUser("operator");
    client = await loginAs(operator.username, operator.password);

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP2, portSpec: "443" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [{ ip: IP2, ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https", cpes: [CPE2] }] }],
      });
    hostId = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP2).executeTakeFirstOrThrow()).id;

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE2,
        cves: JSON.stringify([{ id: CVE2, cvssScore: 7.5, cvssSeverity: "HIGH", description: "expiring acceptance" }]),
      })
      .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: (eb) => eb.ref("excluded.cves") }))
      .execute();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP2).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE2).execute();
    await deleteTestUser(operator.id);
    await deleteTestAgent(agent.id);
    // Only the last describe in the file may close the pool - doing it
    // earlier breaks every block after it.
    await closeDb();
  });

  it("suppresses the risk indicator while the acceptance is still in date", async () => {
    const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
    await client
      .put("/api/finding-triage")
      .send({ kind: "cve", hostId, cveId: CVE2, state: "fixed", reviewAt: future });

    const res = await client.get(`/api/hosts?q=${IP2}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host.cve_count).toBe(0);
  });

  it("counts again once the review date has passed, without the row being deleted", async () => {
    const past = new Date(Date.now() - 86_400_000).toISOString();
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: CVE2, state: "fixed", reviewAt: past });

    const res = await client.get(`/api/hosts?q=${IP2}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host.cve_count).toBe(1);

    // The decision itself is kept - who decided what and when is the
    // history worth preserving; expiry only stops it being honored.
    const row = await db
      .selectFrom("finding_triage")
      .select(["state", "created_by"])
      .where("host_id", "=", hostId)
      .executeTakeFirstOrThrow();
    expect(row.state).toBe("fixed");
    expect(row.created_by).toBe(operator.username);
  });

  it("flags the finding as expired on the fleet-wide list so it can be re-reviewed", async () => {
    const res = await client.get("/api/vulnerabilities");
    const row = res.body.items.find((v: { host_id: string; cve_id: string }) => v.host_id === hostId && v.cve_id === CVE2);
    expect(row.triage_state).toBe("fixed");
    expect(row.triage_expired).toBe(true);
  });

  it("re-triaging without a review date clears the old expiry rather than inheriting it", async () => {
    await client.put("/api/finding-triage").send({ kind: "cve", hostId, cveId: CVE2, state: "false_positive" });

    const row = await db
      .selectFrom("finding_triage")
      .select(["review_at"])
      .where("host_id", "=", hostId)
      .executeTakeFirstOrThrow();
    expect(row.review_at).toBeNull();

    const res = await client.get(`/api/hosts?q=${IP2}`);
    const host = res.body.items.find((h: { id: string }) => h.id === hostId);
    expect(host.cve_count).toBe(0);
  });
});
