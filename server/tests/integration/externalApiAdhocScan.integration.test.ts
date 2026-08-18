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
    await closeDb();
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
