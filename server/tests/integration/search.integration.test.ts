import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// Documentation-range IPv6 address (2001:db8::/32 is reserved for
// documentation/examples, RFC 3849) - can't collide with a real host if
// this suite ever runs against a copy of a real database.
const IPV6_IP = "2001:db8:9::42";

interface HostRow {
  id: string;
  ip: string;
}

describe("dashboard search matches an IPv6 host by address and by CIDR", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-search-ipv6-agent");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IPV6_IP, portSpec: "22" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [{ ip: IPV6_IP, ports: [{ port: 22, protocol: "tcp", state: "open" }] }],
      });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "=", IPV6_IP).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("matches on the exact IPv6 address", async () => {
    const res = await client.get(`/api/hosts?q=${encodeURIComponent(IPV6_IP)}`);
    expect(res.status).toBe(200);
    expect((res.body.items as HostRow[]).some((h) => h.ip === IPV6_IP)).toBe(true);
  });

  it("matches via IPv6 CIDR containment - this is the bug that was fixed (isIPv4Cidr previously gated the SQL, silently rejecting any IPv6 CIDR search)", async () => {
    const res = await client.get(`/api/hosts?q=${encodeURIComponent("2001:db8:9::/64")}`);
    expect(res.status).toBe(200);
    expect((res.body.items as HostRow[]).some((h) => h.ip === IPV6_IP)).toBe(true);
  });

  it("does not match an unrelated IPv6 CIDR", async () => {
    const res = await client.get(`/api/hosts?q=${encodeURIComponent("2001:db8:99::/64")}`);
    expect(res.status).toBe(200);
    expect((res.body.items as HostRow[]).some((h) => h.ip === IPV6_IP)).toBe(false);
  });
});
