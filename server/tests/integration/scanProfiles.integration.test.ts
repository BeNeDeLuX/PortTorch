import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
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

// Class E (240.0.0.0/4) - reserved, never a real target, so this can't
// collide with genuine data even run against a copy of a real database -
// same convention as trends.integration.test.ts.
const IP_A = "240.7.1.1";

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

describe("scan profiles - CRUD", () => {
  let admin: TestUser;
  let client: SessionClient;
  const createdIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await db.deleteFrom("scan_profiles").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
  });

  afterEach(async () => {
    while (createdIds.length) {
      await db.deleteFrom("scan_profiles").where("id", "=", createdIds.pop()!).execute();
    }
  });

  it("creates, lists, patches, and deletes a custom profile", async () => {
    const createRes = await client
      .post("/api/scan-profiles")
      .send({ name: "it-web-only", nseScripts: ["http-title", "ssl-cert"] });
    expect(createRes.status).toBe(201);
    createdIds.push(createRes.body.id);
    expect(createRes.body).toMatchObject({ name: "it-web-only", nse_scripts: ["http-title", "ssl-cert"] });

    const listRes = await client.get("/api/scan-profiles");
    expect(listRes.body.map((p: { id: string }) => p.id)).toContain(createRes.body.id);

    const patchRes = await client
      .patch(`/api/scan-profiles/${createRes.body.id}`)
      .send({ nseScripts: ["http-title", "ssl-cert", "banner"] });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body.nse_scripts).toEqual(["http-title", "ssl-cert", "banner"]);

    const deleteRes = await client.delete(`/api/scan-profiles/${createRes.body.id}`);
    expect(deleteRes.status).toBe(204);
    createdIds.pop();

    const listAfterDelete = await client.get("/api/scan-profiles");
    expect(listAfterDelete.body.map((p: { id: string }) => p.id)).not.toContain(createRes.body.id);
  });

  it("rejects an unrecognized NSE script name", async () => {
    const res = await client
      .post("/api/scan-profiles")
      .send({ name: "it-bad-script", nseScripts: ["not-a-real-nse-script"] });
    expect(res.status).toBe(400);
  });

  it("rejects a duplicate profile name", async () => {
    const first = await client.post("/api/scan-profiles").send({ name: "it-dup-name", nseScripts: ["banner"] });
    createdIds.push(first.body.id);

    const second = await client.post("/api/scan-profiles").send({ name: "it-dup-name", nseScripts: ["ssh-hostkey"] });
    expect(second.status).toBe(409);
  });
});

describe("scan profiles - rescan snapshot behavior", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let profileId: string;
  const createdScanRequestIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-profile-rescan-agent");
    await ingestOpenPort(agent, IP_A, 22);

    const profileRes = await client
      .post("/api/scan-profiles")
      .send({ name: "it-snapshot-profile", nseScripts: ["banner", "ssh-hostkey"] });
    profileId = profileRes.body.id;
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await db.deleteFrom("scan_profiles").where("id", "=", profileId).execute();
    await db.deleteFrom("hosts").where("ip", "=", IP_A).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("snapshots a custom profile's scripts onto the scan_request at creation time, unaffected by a later profile edit/delete", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const rescanRes = await client
      .post(`/api/hosts/${host.id}/rescan`)
      .send({ profile: { kind: "custom", profileId } });
    expect(rescanRes.status).toBe(201);
    createdScanRequestIds.push(rescanRes.body.id);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nse_scripts", "nse_profile_label"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(requestRow.nse_profile).toBe("custom");
    expect(requestRow.nse_scripts).toEqual(["banner", "ssh-hostkey"]);
    expect(requestRow.nse_profile_label).toBe("it-snapshot-profile");

    // Editing the profile afterward must not retroactively change the
    // already-created scan_requests row's snapshot.
    await client.patch(`/api/scan-profiles/${profileId}`).send({ nseScripts: ["http-title"] });
    const afterEdit = await db
      .selectFrom("scan_requests")
      .select(["nse_scripts"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(afterEdit.nse_scripts).toEqual(["banner", "ssh-hostkey"]);
  });

  it("defaults to the 'default' profile when no profile is specified", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const rescanRes = await client.post(`/api/hosts/${host.id}/rescan`);
    expect(rescanRes.status).toBe(201);
    createdScanRequestIds.push(rescanRes.body.id);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nse_scripts", "nse_profile_label"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(requestRow.nse_profile).toBe("default");
    expect(requestRow.nse_scripts).toBeNull();
    expect(requestRow.nse_profile_label).toBe("Default");
  });

  it("rejects an unknown custom profileId with a 400, not a 500", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const res = await client
      .post(`/api/hosts/${host.id}/rescan`)
      .send({ profile: { kind: "custom", profileId: "00000000-0000-0000-0000-000000000000" } });
    expect(res.status).toBe(400);
  });
});
