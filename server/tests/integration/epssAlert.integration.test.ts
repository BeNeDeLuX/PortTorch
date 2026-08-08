import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { checkHighEpssAlerts } from "../../src/cve/epssSync";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.6.3.1";
const PORT = 8443;
const CPE = "cpe:/a:porttorch-test:epssalert:1.0";

// Default config.epssAlertThreshold is 0.5 (EPSS_ALERT_THRESHOLD isn't set
// in vitest.integration.config.ts's env) - these are picked well clear of
// it on each side so the test isn't sensitive to float rounding.
const CVE_HIGH = "CVE-1999-2001"; // epss 0.9 - above threshold, never alerted
const CVE_LOW = "CVE-1999-2002"; // epss 0.1 - below threshold
const CVE_ALREADY_ALERTED = "CVE-1999-2003"; // epss 0.95, but already alerted once
const CVE_ORPHAN = "CVE-1999-2004"; // epss 0.99, not referenced by any open port

describe("checkHighEpssAlerts", () => {
  let agent: TestAgent;
  let alreadyAlertedAt: Date;

  beforeAll(async () => {
    agent = await createTestAgent("it-epss-alert-agent");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: String(PORT) });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: jobRes.body.id, hosts: [{ ip: IP, ports: [{ port: PORT, protocol: "tcp", state: "open", cpes: [CPE] }] }] });

    await db
      .insertInto("cve_cache")
      .values({
        cpe: CPE,
        cves: JSON.stringify([
          { id: CVE_HIGH, description: "high epss", cvssScore: 7.5, cvssSeverity: "HIGH", published: null },
          { id: CVE_LOW, description: "low epss", cvssScore: 7.5, cvssSeverity: "HIGH", published: null },
        ]),
      })
      .execute();

    alreadyAlertedAt = new Date(Date.now() - 60_000);
    await db
      .insertInto("epss_cache")
      .values([
        { cve_id: CVE_HIGH, epss: 0.9, percentile: 0.95, alert_sent_at: null },
        { cve_id: CVE_LOW, epss: 0.1, percentile: 0.2, alert_sent_at: null },
        { cve_id: CVE_ALREADY_ALERTED, epss: 0.95, percentile: 0.99, alert_sent_at: alreadyAlertedAt.toISOString() },
        { cve_id: CVE_ORPHAN, epss: 0.99, percentile: 0.99, alert_sent_at: null },
      ])
      .execute();

    await checkHighEpssAlerts();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("epss_cache").where("cve_id", "in", [CVE_HIGH, CVE_LOW, CVE_ALREADY_ALERTED, CVE_ORPHAN]).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("marks a CVE at/above the threshold with open, matching ports as alerted", async () => {
    const row = await db.selectFrom("epss_cache").select(["alert_sent_at"]).where("cve_id", "=", CVE_HIGH).executeTakeFirstOrThrow();
    expect(row.alert_sent_at).not.toBeNull();
  });

  it("leaves a CVE below the threshold untouched", async () => {
    const row = await db.selectFrom("epss_cache").select(["alert_sent_at"]).where("cve_id", "=", CVE_LOW).executeTakeFirstOrThrow();
    expect(row.alert_sent_at).toBeNull();
  });

  it("never re-processes a CVE that was already alerted, even if still above the threshold", async () => {
    const row = await db
      .selectFrom("epss_cache")
      .select(["alert_sent_at"])
      .where("cve_id", "=", CVE_ALREADY_ALERTED)
      .executeTakeFirstOrThrow();
    expect(new Date(row.alert_sent_at!).getTime()).toBe(alreadyAlertedAt.getTime());
  });

  it("marks a high-EPSS CVE with no currently-matching open port as seen too, so it isn't rechecked forever", async () => {
    const row = await db.selectFrom("epss_cache").select(["alert_sent_at"]).where("cve_id", "=", CVE_ORPHAN).executeTakeFirstOrThrow();
    expect(row.alert_sent_at).not.toBeNull();
  });
});
