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

describe("ad-hoc scans", () => {
  let operator: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let profileId: string;
  const createdScanRequestIds: string[] = [];

  beforeAll(async () => {
    operator = await createTestUser("operator");
    client = await loginAs(operator.username, operator.password);
    agent = await createTestAgent("it-adhoc-agent");

    const profileRes = await client
      .post("/api/scan-profiles")
      .send({ name: "it-adhoc-profile", nseScripts: ["banner"] });
    // Scan profile creation is admin-only - an operator can't create one,
    // so fall back to inserting directly for this fixture (only the
    // profile *selection* at scan-request time is under test here, not
    // profile-page access control, which scanProfiles.integration.test.ts
    // already covers).
    if (profileRes.status !== 201) {
      const row = await db
        .insertInto("scan_profiles")
        .values({ name: `it-adhoc-profile-${agent.id}`, nse_scripts: ["banner"] })
        .returning(["id"])
        .executeTakeFirstOrThrow();
      profileId = row.id;
    } else {
      profileId = profileRes.body.id;
    }
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    await db.deleteFrom("scan_profiles").where("id", "=", profileId).execute();
    await deleteTestUser(operator.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("creates a scan_requests row for a DNS-hostname target with a custom NSE profile, host_id null", async () => {
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "internal-host.example.test",
      portSpec: "1-1000",
      profile: { kind: "custom", profileId },
    });
    expect(res.status).toBe(201);
    createdScanRequestIds.push(res.body.id);
    expect(res.body.nse_profile_label).toBe(
      (await db.selectFrom("scan_profiles").select(["name"]).where("id", "=", profileId).executeTakeFirstOrThrow()).name
    );

    const row = await db
      .selectFrom("scan_requests")
      .selectAll()
      .where("id", "=", res.body.id)
      .executeTakeFirstOrThrow();
    expect(row.host_id).toBeNull();
    expect(row.target_spec).toBe("internal-host.example.test");
    expect(row.port_spec).toBe("1-1000");
    expect(row.requested_by).toBe(operator.username);
    expect(row.nse_profile).toBe("custom");
    expect(row.status).toBe("pending");
  });

  it("defaults to Default/Off profiles when neither is specified", async () => {
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "240.9.6.1",
      portSpec: "443",
    });
    expect(res.status).toBe(201);
    createdScanRequestIds.push(res.body.id);

    const row = await db
      .selectFrom("scan_requests")
      .select(["nse_profile", "nuclei_profile"])
      .where("id", "=", res.body.id)
      .executeTakeFirstOrThrow();
    expect(row.nse_profile).toBe("default");
    expect(row.nuclei_profile).toBe("off");
  });

  it("is claimable by the scanner via GET /api/ingest/scan-requests/next, targetSpec unresolved", async () => {
    // Its own fresh scanner agent, not the shared `agent` - the earlier
    // tests in this file also create (and never claim) pending
    // scan_requests rows against `agent`, and /next always claims the
    // oldest pending row for that agent. Reusing `agent` here would make
    // this test's outcome depend on exactly what ran before it.
    const freshAgent = await createTestAgent("it-adhoc-next-agent");
    const createRes = await client.post("/api/adhoc-scans").send({
      scannerAgentId: freshAgent.id,
      targetSpec: "another-internal-host.example.test",
      portSpec: "22,443",
    });
    expect(createRes.status).toBe(201);
    createdScanRequestIds.push(createRes.body.id);

    const nextRes = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${freshAgent.apiKey}`);
    expect(nextRes.status).toBe(200);
    expect(nextRes.body.targetSpec).toBe("another-internal-host.example.test");
    expect(nextRes.body.portSpec).toBe("22,443");

    await deleteTestAgent(freshAgent.id);
  });

  it("rejects an unknown scanner agent with a 400", async () => {
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: "00000000-0000-0000-0000-000000000000",
      targetSpec: "240.9.6.2",
      portSpec: "80",
    });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown custom NSE profileId with a 400, not a 500", async () => {
    const res = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "240.9.6.3",
      portSpec: "80",
      profile: { kind: "custom", profileId: "00000000-0000-0000-0000-000000000000" },
    });
    expect(res.status).toBe(400);
  });

  it("rejects a scanner agent the acting user isn't allowed to use", async () => {
    const restricted = await createTestUser("operator");
    const otherAgent = await createTestAgent("it-adhoc-other-agent");
    // No user_scanner_agents row for `restricted` covering `agent` -
    // matches the whole-fleet-restriction idiom (absence of any row
    // scopes a user to nothing at all once at least one row exists for
    // them - see auth/scannerScope.ts). This must be inserted BEFORE
    // loginAs: allowedScannerAgentIds is loaded into the session once at
    // login and stays stale for the rest of that session (CLAUDE.md's
    // documented trust model) - restricting after login would have no
    // effect on the session already established below.
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: otherAgent.id }).execute();
    const restrictedClient = await loginAs(restricted.username, restricted.password);

    const res = await restrictedClient.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: "240.9.6.4",
      portSpec: "80",
    });
    expect(res.status).toBe(403);

    await deleteTestUser(restricted.id);
    await deleteTestAgent(otherAgent.id);
  });
});
