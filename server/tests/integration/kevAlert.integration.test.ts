import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { checkKevAlerts } from "../../src/cve/kevSync";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.6.4.1";
const PORT = 8443;
const CPE = "cpe:/a:porttorch-test:kevalert:1.0";

// Unlike EPSS's numeric threshold, KEV alerting has no "below threshold"
// case - a CVE is either on the catalog or it isn't, so there's no
// equivalent of epssAlert's CVE_LOW here.
const CVE_MATCHED = "CVE-1999-3001"; // affects an open port, never alerted
const CVE_ALREADY_ALERTED = "CVE-1999-3002"; // affects an open port, but already alerted once
const CVE_ORPHAN = "CVE-1999-3003"; // not referenced by any open port

describe("checkKevAlerts", () => {
  let agent: TestAgent;
  let alreadyAlertedAt: Date;

  beforeAll(async () => {
    agent = await createTestAgent("it-kev-alert-agent");

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
          { id: CVE_MATCHED, description: "kev matched", cvssScore: 8.1, cvssSeverity: "HIGH", published: null },
          { id: CVE_ALREADY_ALERTED, description: "kev already alerted", cvssScore: 8.1, cvssSeverity: "HIGH", published: null },
        ]),
      })
      .execute();

    alreadyAlertedAt = new Date(Date.now() - 60_000);
    await db
      .insertInto("kev_cache")
      .values([
        { cve_id: CVE_MATCHED, vulnerability_name: "Matched Vuln", known_ransomware_campaign_use: "Unknown", alert_sent_at: null },
        { cve_id: CVE_ALREADY_ALERTED, vulnerability_name: "Already Alerted Vuln", known_ransomware_campaign_use: "Known", alert_sent_at: alreadyAlertedAt.toISOString() },
        { cve_id: CVE_ORPHAN, vulnerability_name: "Orphan Vuln", known_ransomware_campaign_use: "Unknown", alert_sent_at: null },
      ])
      .execute();

    await checkKevAlerts();
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("cve_cache").where("cpe", "=", CPE).execute();
    await db.deleteFrom("kev_cache").where("cve_id", "in", [CVE_MATCHED, CVE_ALREADY_ALERTED, CVE_ORPHAN]).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("marks a KEV entry with open, matching ports as alerted", async () => {
    const row = await db.selectFrom("kev_cache").select(["alert_sent_at"]).where("cve_id", "=", CVE_MATCHED).executeTakeFirstOrThrow();
    expect(row.alert_sent_at).not.toBeNull();
  });

  it("never re-processes a KEV entry that was already alerted", async () => {
    const row = await db
      .selectFrom("kev_cache")
      .select(["alert_sent_at"])
      .where("cve_id", "=", CVE_ALREADY_ALERTED)
      .executeTakeFirstOrThrow();
    expect(new Date(row.alert_sent_at!).getTime()).toBe(alreadyAlertedAt.getTime());
  });

  it("marks a KEV entry with no currently-matching open port as seen too, so it isn't rechecked forever", async () => {
    const row = await db.selectFrom("kev_cache").select(["alert_sent_at"]).where("cve_id", "=", CVE_ORPHAN).executeTakeFirstOrThrow();
    expect(row.alert_sent_at).not.toBeNull();
  });
});
