import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestApiToken,
  deleteTestAgent,
  deleteTestApiToken,
  getApp,
  type TestAgent,
  type TestApiToken,
} from "./helpers";

// POST /api/v1/scans/adhoc - the External API's counterpart to the
// dashboard's own Ad-hoc Scans page (adhocScans/routes.ts). Unlike every
// other route in integrations/routes.ts, this one doesn't require an
// existing host at all - a SOAR tool scanning a target it just learned
// about from outside this app entirely.
describe("external API - POST /scans/adhoc", () => {
  let agent: TestAgent;
  let token: TestApiToken;
  let nseProfileId: string;
  let nucleiProfileId: string;
  const createdScanRequestIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-extapi-adhoc-agent");
    token = await createTestApiToken("it-extapi-adhoc-token");

    const nseProfileRow = await db
      .insertInto("scan_profiles")
      .values({ name: "it-extapi-adhoc-nse", nse_scripts: ["banner", "ssh-hostkey"] })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    nseProfileId = nseProfileRow.id;

    const nucleiProfileRow = await db
      .insertInto("nuclei_profiles")
      .values({ name: "it-extapi-adhoc-nuclei", tags: ["cve"], severities: ["critical", "high"], excluded_tags: [] })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    nucleiProfileId = nucleiProfileRow.id;
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await db.deleteFrom("scan_profiles").where("id", "=", nseProfileId).execute();
    await db.deleteFrom("nuclei_profiles").where("id", "=", nucleiProfileId).execute();
    await deleteTestAgent(agent.id);
    await deleteTestApiToken(token.id);
  });

  it("queues a scan_requests row with host_id null, resolves Custom NSE/nuclei profiles by name", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({
        scannerAgent: agent.name,
        targetSpec: "240.9.7.1",
        portSpec: "1-1000",
        profile: "it-extapi-adhoc-nse",
        nucleiProfile: "it-extapi-adhoc-nuclei",
      });
    expect(res.status).toBe(201);
    expect(res.body.profile).toBe("it-extapi-adhoc-nse");
    expect(res.body.nucleiProfile).toBe("it-extapi-adhoc-nuclei");
    expect(res.body.scannerAgentName).toBe(agent.name);
    createdScanRequestIds.push(res.body.scanRequestId);

    const row = await db
      .selectFrom("scan_requests")
      .selectAll()
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(row.host_id).toBeNull();
    expect(row.target_spec).toBe("240.9.7.1");
    expect(row.port_spec).toBe("1-1000");
    expect(row.requested_by).toBe(`api-token:${token.name}`);
    expect(row.nse_profile).toBe("custom");
    expect(row.nse_scripts).toEqual(["banner", "ssh-hostkey"]);
    expect(row.nuclei_profile).toBe("custom");
    expect(row.nuclei_tags).toEqual(["cve"]);
    expect(row.status).toBe("pending");
  });

  it("defaults to Default/off when profile/nucleiProfile are omitted", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: agent.name, targetSpec: "240.9.7.2", portSpec: "443" });
    expect(res.status).toBe(201);
    expect(res.body.profile).toBe("Default");
    createdScanRequestIds.push(res.body.scanRequestId);

    const row = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nuclei_profile"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(row.nse_profile).toBe("default");
    expect(row.nuclei_profile).toBe("off");
  });

  it("accepts 'safe' as the nuclei profile case-insensitively", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: agent.name, targetSpec: "240.9.7.3", portSpec: "80", nucleiProfile: "SAFE" });
    expect(res.status).toBe(201);
    createdScanRequestIds.push(res.body.scanRequestId);

    const row = await db
      .selectFrom("scan_requests")
      .select(["nuclei_profile"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(row.nuclei_profile).toBe("safe");
  });

  it("rejects an unknown scanner agent name with a 400", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: "does-not-exist-agent", targetSpec: "240.9.7.4", portSpec: "80" });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown NSE profile name with a 400, not a 500", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: agent.name, targetSpec: "240.9.7.5", portSpec: "80", profile: "does-not-exist" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/does-not-exist/);
  });

  it("rejects an unknown nuclei profile name with a 400, not a 500", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: agent.name, targetSpec: "240.9.7.6", portSpec: "80", nucleiProfile: "does-not-exist" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/does-not-exist/);
  });

  it("rejects a request with no bearer token", async () => {
    const res = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .send({ scannerAgent: agent.name, targetSpec: "240.9.7.7", portSpec: "80" });
    expect(res.status).toBe(401);
  });

  it("is claimable by the scanner via GET /api/ingest/scan-requests/next", async () => {
    const freshAgent = await createTestAgent("it-extapi-adhoc-next-agent");
    const createRes = await request(getApp())
      .post("/api/v1/scans/adhoc")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ scannerAgent: freshAgent.name, targetSpec: "240.9.7.8", portSpec: "22,443" });
    expect(createRes.status).toBe(201);
    createdScanRequestIds.push(createRes.body.scanRequestId);

    const nextRes = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${freshAgent.apiKey}`);
    expect(nextRes.status).toBe(200);
    expect(nextRes.body.targetSpec).toBe("240.9.7.8");
    expect(nextRes.body.portSpec).toBe("22,443");

    await deleteTestAgent(freshAgent.id);
  });
});

// Closing the loop from a ticketing/SOAR workflow: mark a finding handled
// so it stops resurfacing, without anyone opening the dashboard.
describe("external API - finding triage", () => {
  let agent: TestAgent;
  let token: TestApiToken;
  let hostId: string;
  const IP = "240.13.1.1";

  beforeAll(async () => {
    agent = await createTestAgent("it-extapi-triage-agent");
    token = await createTestApiToken("it-extapi-triage-token");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "443" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            ip: IP,
            ports: [{ port: 443, protocol: "tcp", state: "open", serviceName: "https" }],
            nucleiFindings: [
              { port: 443, templateId: "extapi-tpl", name: "n", severity: "high", matchedAt: "https://240.13.1.1/x" },
            ],
          },
        ],
      });
    hostId = (await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow()).id;
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await deleteTestApiToken(token.id);
    await closeDb();
  });

  const put = () => request(getApp()).put("/api/v1/findings/triage").set("Authorization", `Bearer ${token.token}`);
  const del = () => request(getApp()).delete("/api/v1/findings/triage").set("Authorization", `Bearer ${token.token}`);

  it("triages a CVE by ip, attributing it to the token rather than a user", async () => {
    const res = await put().send({ ip: IP, cveId: "CVE-1999-7001", state: "fixed", note: "patched via TICKET-42" });
    expect(res.status).toBe(200);
    expect(res.body.state).toBe("fixed");

    const row = await db
      .selectFrom("finding_triage")
      .selectAll()
      .where("host_id", "=", hostId)
      .where("kind", "=", "cve")
      .executeTakeFirstOrThrow();
    expect(row.cve_id).toBe("CVE-1999-7001");
    expect(row.created_by).toBe(`api-token:${token.name}`);
    expect(row.note).toBe("patched via TICKET-42");
  });

  it("triages a nuclei finding by template id and matched URL", async () => {
    const res = await put().send({
      ip: IP,
      templateId: "extapi-tpl",
      matchedAt: "https://240.13.1.1/x",
      state: "false_positive",
    });
    expect(res.status).toBe(200);

    const list = await request(getApp())
      .get("/api/v1/hosts/lookup?ip=" + IP)
      .set("Authorization", `Bearer ${token.token}`);
    expect(list.status).toBe(200);
  });

  it("accepts a review date so the decision expires instead of lasting forever", async () => {
    const reviewAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
    const res = await put().send({ ip: IP, cveId: "CVE-1999-7002", state: "accepted_risk", reviewAt });
    expect(res.status).toBe(200);
    expect(res.body.reviewAt).toBeTruthy();
  });

  it("rejects a body that identifies neither finding kind", async () => {
    const res = await put().send({ ip: IP, state: "fixed" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/cveId/);
  });

  it("rejects a half-specified nuclei finding", async () => {
    const res = await put().send({ ip: IP, templateId: "extapi-tpl", state: "fixed" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/matchedAt/);
  });

  it("rejects mixing both finding kinds in one call", async () => {
    const res = await put().send({
      ip: IP,
      cveId: "CVE-1999-7003",
      templateId: "extapi-tpl",
      matchedAt: "https://240.13.1.1/x",
      state: "fixed",
    });
    expect(res.status).toBe(400);
  });

  it("404s for an unknown host", async () => {
    const res = await put().send({ ip: "240.13.9.9", cveId: "CVE-1999-7004", state: "fixed" });
    expect(res.status).toBe(404);
  });

  it("clears triage again, and 404s when there was nothing to clear", async () => {
    expect((await del().send({ ip: IP, cveId: "CVE-1999-7001" })).status).toBe(204);
    expect((await del().send({ ip: IP, cveId: "CVE-1999-7001" })).status).toBe(404);
  });

  it("requires a token", async () => {
    const res = await request(getApp()).put("/api/v1/findings/triage").send({ ip: IP, cveId: "X", state: "fixed" });
    expect(res.status).toBe(401);
  });
});
