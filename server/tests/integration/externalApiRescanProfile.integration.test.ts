import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestApiToken, deleteTestAgent, deleteTestApiToken, getApp, type TestAgent, type TestApiToken } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target, so this can't
// collide with genuine data - same convention as scanProfiles.integration.test.ts.
const IP_A = "240.7.2.1";

async function ingestOpenPort(agent: TestAgent, ip: string, port: number): Promise<void> {
  const jobRes = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec: ip, portSpec: String(port) });
  await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId: jobRes.body.id, hosts: [{ ip, ports: [{ port, protocol: "tcp", state: "open" }] }] });
}

// The External API (integrations/routes.ts) accepts a flat, name-based
// `profile` string rather than the dashboard's {kind, profileId} shape -
// an external caller has no reason to know a Custom profile's internal
// uuid, only the name an admin gave it on the Scan Profiles page.
describe("external API - rescan profile parameter", () => {
  let agent: TestAgent;
  let token: TestApiToken;
  let profileId: string;
  const createdScanRequestIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-extapi-profile-agent");
    token = await createTestApiToken("it-extapi-profile-token");
    await ingestOpenPort(agent, IP_A, 22);

    const profileRow = await db
      .insertInto("scan_profiles")
      .values({ name: "it-extapi-profile", nse_scripts: ["banner", "ssh-hostkey"] })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    profileId = profileRow.id;
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await db.deleteFrom("scan_profiles").where("id", "=", profileId).execute();
    await db.deleteFrom("hosts").where("ip", "=", IP_A).execute();
    await deleteTestAgent(agent.id);
    await deleteTestApiToken(token.id);
    await closeDb();
  });

  it("resolves a Custom profile by name and snapshots its scripts", async () => {
    const res = await request(getApp())
      .post("/api/v1/hosts/rescan")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ ip: IP_A, profile: "it-extapi-profile" });
    expect(res.status).toBe(201);
    expect(res.body.profile).toBe("it-extapi-profile");
    createdScanRequestIds.push(res.body.scanRequestId);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nse_scripts", "nse_profile_label"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(requestRow.nse_profile).toBe("custom");
    expect(requestRow.nse_scripts).toEqual(["banner", "ssh-hostkey"]);
    expect(requestRow.nse_profile_label).toBe("it-extapi-profile");
  });

  it("accepts 'all_safe' case-insensitively", async () => {
    const res = await request(getApp())
      .post("/api/v1/hosts/rescan")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ ip: IP_A, profile: "ALL_SAFE" });
    expect(res.status).toBe(201);
    createdScanRequestIds.push(res.body.scanRequestId);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nse_profile"])
      .where("id", "=", res.body.scanRequestId)
      .executeTakeFirstOrThrow();
    expect(requestRow.nse_profile).toBe("all_safe");
  });

  it("defaults to Default when profile is omitted, same as before this existed", async () => {
    const res = await request(getApp())
      .post("/api/v1/hosts/rescan")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ ip: IP_A });
    expect(res.status).toBe(201);
    expect(res.body.profile).toBe("Default");
    createdScanRequestIds.push(res.body.scanRequestId);
  });

  it("rejects an unknown profile name with a 400 naming the valid options, not a 500", async () => {
    const res = await request(getApp())
      .post("/api/v1/hosts/rescan")
      .set("Authorization", `Bearer ${token.token}`)
      .send({ ip: IP_A, profile: "does-not-exist" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/does-not-exist/);
  });
});
