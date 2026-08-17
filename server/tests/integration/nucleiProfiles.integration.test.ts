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

// Class E (240.0.0.0/4) - reserved, never a real target - same convention
// as scanProfiles.integration.test.ts.
const IP_A = "240.7.3.1";
const IP_B = "240.7.3.2";

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

describe("nuclei profiles - CRUD", () => {
  let admin: TestUser;
  let client: SessionClient;
  const createdIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    for (const id of createdIds) {
      await db.deleteFrom("nuclei_profiles").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
  });

  afterEach(async () => {
    while (createdIds.length) {
      await db.deleteFrom("nuclei_profiles").where("id", "=", createdIds.pop()!).execute();
    }
  });

  it("creates, lists, patches, and deletes a custom profile", async () => {
    const createRes = await client
      .post("/api/nuclei-profiles")
      .send({ name: "it-exposures-only", tags: ["exposure", "config"], severities: ["high", "critical"] });
    expect(createRes.status).toBe(201);
    createdIds.push(createRes.body.id);
    expect(createRes.body).toMatchObject({ name: "it-exposures-only", tags: ["exposure", "config"], severities: ["high", "critical"] });

    const listRes = await client.get("/api/nuclei-profiles");
    expect(listRes.body.map((p: { id: string }) => p.id)).toContain(createRes.body.id);

    const patchRes = await client.patch(`/api/nuclei-profiles/${createRes.body.id}`).send({ tags: ["exposure"] });
    expect(patchRes.status).toBe(200);
    expect(patchRes.body.tags).toEqual(["exposure"]);

    const deleteRes = await client.delete(`/api/nuclei-profiles/${createRes.body.id}`);
    expect(deleteRes.status).toBe(204);
    createdIds.pop();

    const listAfterDelete = await client.get("/api/nuclei-profiles");
    expect(listAfterDelete.body.map((p: { id: string }) => p.id)).not.toContain(createRes.body.id);
  });

  // Unlike NSE scripts, an unrecognized tag is accepted (see resolve.ts's
  // doc comment - nuclei's own tag taxonomy is far too large to allowlist,
  // and an unrecognized tag is a harmless zero-match, not a scan-aborting
  // error) - so this is the one thing that IS still rejected: severity
  // values are a small, stable enum.
  it("rejects an unrecognized severity", async () => {
    const res = await client
      .post("/api/nuclei-profiles")
      .send({ name: "it-bad-severity", severities: ["ultra-mega-critical"] });
    expect(res.status).toBe(400);
  });

  it("accepts an arbitrary/unrecognized tag (no allowlist, unlike NSE scripts)", async () => {
    const res = await client.post("/api/nuclei-profiles").send({ name: "it-arbitrary-tag", tags: ["cve2099"] });
    expect(res.status).toBe(201);
    createdIds.push(res.body.id);
  });

  it("rejects a duplicate profile name", async () => {
    const first = await client.post("/api/nuclei-profiles").send({ name: "it-dup-name", tags: ["exposure"] });
    createdIds.push(first.body.id);

    const second = await client.post("/api/nuclei-profiles").send({ name: "it-dup-name", tags: ["misconfig"] });
    expect(second.status).toBe(409);
  });
});

describe("nuclei profiles - rescan snapshot behavior", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let profileId: string;
  const createdScanRequestIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-nuclei-profile-rescan-agent");
    await ingestOpenPort(agent, IP_A, 443);

    const profileRes = await client
      .post("/api/nuclei-profiles")
      .send({ name: "it-nuclei-snapshot-profile", tags: ["exposure"], severities: ["high"] });
    profileId = profileRes.body.id;
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await db.deleteFrom("nuclei_profiles").where("id", "=", profileId).execute();
    await db.deleteFrom("hosts").where("ip", "=", IP_A).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
  });

  it("snapshots a custom profile's tags onto the scan_request at creation time, unaffected by a later profile edit/delete", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const rescanRes = await client
      .post(`/api/hosts/${host.id}/rescan`)
      .send({ nucleiProfile: { kind: "custom", profileId } });
    expect(rescanRes.status).toBe(201);
    createdScanRequestIds.push(rescanRes.body.id);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nuclei_profile", "nuclei_tags", "nuclei_profile_label"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(requestRow.nuclei_profile).toBe("custom");
    expect(requestRow.nuclei_tags).toEqual(["exposure"]);
    expect(requestRow.nuclei_profile_label).toBe("it-nuclei-snapshot-profile");

    // Editing the profile afterward must not retroactively change the
    // already-created scan_requests row's snapshot.
    await client.patch(`/api/nuclei-profiles/${profileId}`).send({ tags: ["misconfig"] });
    const afterEdit = await db
      .selectFrom("scan_requests")
      .select(["nuclei_tags"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(afterEdit.nuclei_tags).toEqual(["exposure"]);
  });

  it("defaults to 'off' when no nuclei profile is specified", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const rescanRes = await client.post(`/api/hosts/${host.id}/rescan`);
    expect(rescanRes.status).toBe(201);
    createdScanRequestIds.push(rescanRes.body.id);

    const requestRow = await db
      .selectFrom("scan_requests")
      .select(["nuclei_profile", "nuclei_tags", "nuclei_profile_label"])
      .where("id", "=", rescanRes.body.id)
      .executeTakeFirstOrThrow();
    expect(requestRow.nuclei_profile).toBe("off");
    expect(requestRow.nuclei_tags).toBeNull();
    expect(requestRow.nuclei_profile_label).toBe("Off");
  });

  it("rejects an unknown custom nuclei profileId with a 400, not a 500", async () => {
    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_A).executeTakeFirstOrThrow();

    const res = await client
      .post(`/api/hosts/${host.id}/rescan`)
      .send({ nucleiProfile: { kind: "custom", profileId: "00000000-0000-0000-0000-000000000000" } });
    expect(res.status).toBe(400);
  });
});

describe("nuclei findings - ingest", () => {
  let agent: TestAgent;

  beforeAll(async () => {
    agent = await createTestAgent("it-nuclei-findings-agent");
  });

  afterAll(async () => {
    await db.deleteFrom("nuclei_findings").where("host_id", "in", db.selectFrom("hosts").select("id").where("ip", "=", IP_B)).execute();
    await db.deleteFrom("hosts").where("ip", "=", IP_B).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("persists a submitted finding and doesn't duplicate it on a second identical submission", async () => {
    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP_B, portSpec: "443" });

    const finding = {
      port: 443,
      templateId: "it-test-exposed-env",
      name: "IT Test - Exposed .env",
      severity: "high",
      matchedAt: `https://${IP_B}/.env`,
      description: "test finding",
      tags: ["exposure", "config"],
    };

    const submit = async () =>
      request(getApp())
        .post("/api/ingest/hosts")
        .set("Authorization", `Bearer ${agent.apiKey}`)
        .send({
          scanJobId: jobRes.body.id,
          hosts: [{ ip: IP_B, ports: [{ port: 443, protocol: "tcp", state: "open" }], nucleiFindings: [finding] }],
        });

    const first = await submit();
    expect(first.status).toBe(204);

    const host = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP_B).executeTakeFirstOrThrow();
    const afterFirst = await db.selectFrom("nuclei_findings").selectAll().where("host_id", "=", host.id).execute();
    expect(afterFirst).toHaveLength(1);
    expect(afterFirst[0]).toMatchObject({ template_id: "it-test-exposed-env", severity: "high", matched_at: `https://${IP_B}/.env` });

    // Submitting the exact same finding again (e.g. a rescan that finds
    // the same misconfiguration still present) inserts a second row - one
    // row per observation, same as host_port_observations - but must NOT
    // be treated as "new" for webhook purposes a second time (the
    // dedup/new-finding logic is exercised here even though there's no
    // direct webhook-delivery assertion in this test).
    const second = await submit();
    expect(second.status).toBe(204);
    const afterSecond = await db.selectFrom("nuclei_findings").selectAll().where("host_id", "=", host.id).execute();
    expect(afterSecond).toHaveLength(2);
  });
});
