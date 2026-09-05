import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  loginAs,
  type SessionClient,
  type TestAgent,
  type TestUser,
} from "./helpers";

describe("scan estimate", () => {
  let agent: TestAgent;
  let user: TestUser;
  let client: SessionClient;

  beforeAll(async () => {
    agent = await createTestAgent("it-estimate");
    user = await createTestUser("user");
    client = await loginAs(user.username, user.password);
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(user.id);
    await closeDb();
  });

  it("falls back to masscan's default when the scanner has reported nothing", async () => {
    const res = await client.post("/api/scan-estimate").send({
      targetSpec: "10.0.0.0/24",
      portSpec: "1-1000",
      scannerAgentId: agent.id,
    });
    expect(res.status).toBe(200);
    expect(res.body.addresses).toBe(256);
    expect(res.body.ports).toBe(1000);
    expect(res.body.probes).toBe(256000);
    expect(res.body.rate).toBe(1000);
    // "default", not "scanner" - the difference is what tells an operator
    // whether the number is about their scanner or about a guess.
    expect(res.body.rateSource).toBe("default");
    expect(res.body.masscanSeconds).toBeCloseTo(256, 0);
  });

  it("uses the scanner's own reported rate, and a per-scan override above it", async () => {
    await db
      .updateTable("scanner_agents")
      .set({ base_config: { masscanRate: 250 } as never })
      .where("id", "=", agent.id)
      .execute();

    const reported = await client.post("/api/scan-estimate").send({
      targetSpec: "10.0.0.0/24",
      portSpec: "1-1000",
      scannerAgentId: agent.id,
    });
    expect(reported.body.rate).toBe(250);
    expect(reported.body.rateSource).toBe("scanner");
    // Four times slower than the default above, so four times the time.
    expect(reported.body.masscanSeconds).toBeCloseTo(1024, 0);

    // A dashboard override for that scanner beats what it reported...
    await db
      .updateTable("scanner_agents")
      .set({ config_overrides: JSON.stringify({ masscanRate: 500 }) })
      .where("id", "=", agent.id)
      .execute();
    const overridden = await client.post("/api/scan-estimate").send({
      targetSpec: "10.0.0.0/24",
      portSpec: "1-1000",
      scannerAgentId: agent.id,
    });
    expect(overridden.body.rate).toBe(500);
    expect(overridden.body.rateSource).toBe("scanner");

    // ...and the rate typed into this one form beats both, because that
    // is the rate the scan being estimated will actually run at.
    const perScan = await client.post("/api/scan-estimate").send({
      targetSpec: "10.0.0.0/24",
      portSpec: "1-1000",
      scannerAgentId: agent.id,
      masscanRate: 100,
    });
    expect(perScan.body.rate).toBe(100);
    expect(perScan.body.rateSource).toBe("override");
  });

  it("reports a hostname target as uncountable rather than guessing", async () => {
    const res = await client.post("/api/scan-estimate").send({
      targetSpec: "scanner.internal",
      portSpec: "22,443",
    });
    expect(res.status).toBe(200);
    expect(res.body.addresses).toBeNull();
    expect(res.body.probes).toBeNull();
    expect(res.body.masscanSeconds).toBeNull();
    // The half that is knowable is still reported.
    expect(res.body.ports).toBe(2);
  });

  it("never reveals another scanner's rate to a restricted session", async () => {
    const restricted = await createTestUser("operator");
    const otherAgent = await createTestAgent("it-estimate-other");
    try {
      await db
        .updateTable("scanner_agents")
        .set({ base_config: { masscanRate: 42 } as never })
        .where("id", "=", otherAgent.id)
        .execute();
      await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: agent.id }).execute();
      const restrictedClient = await loginAs(restricted.username, restricted.password);

      const res = await restrictedClient.post("/api/scan-estimate").send({
        targetSpec: "10.0.0.0/24",
        portSpec: "22",
        scannerAgentId: otherAgent.id,
      });
      expect(res.status).toBe(200);
      // Falls back to the default rather than reading a scanner this
      // session is not assigned to - 42 would be a leak, small but real.
      expect(res.body.rate).toBe(1000);
      expect(res.body.rateSource).toBe("default");
    } finally {
      await deleteTestAgent(otherAgent.id);
      await deleteTestUser(restricted.id);
    }
  });

  it("requires authentication", async () => {
    const request = (await import("supertest")).default;
    const { getApp } = await import("./helpers");
    const res = await request(getApp()).post("/api/scan-estimate").send({ targetSpec: "10.0.0.1", portSpec: "22" });
    expect(res.status).toBe(401);
  });
});
