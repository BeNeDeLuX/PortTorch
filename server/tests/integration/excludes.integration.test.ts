import crypto from "crypto";
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
  type TestAgent,
  type TestUser,
} from "./helpers";

interface ExcludesResponse {
  ips: string[];
  ports: string[];
  ipPorts: { ip: string; portSpec: string }[];
}

// scan_excludes with scanner_agent_id IS NULL apply to every scanner (the
// inherited default); a non-null value scopes an exclude to one specific
// scanner *in addition to* the defaults. GET /api/ingest/excludes returns
// the union, not a replacement - this is the one test that exercises that
// union directly rather than trusting it from reading the query.
describe("scan excludes union (global + scanner-scoped)", () => {
  let admin: TestUser;
  let agentA: TestAgent;
  let agentB: TestAgent;
  const excludeIds: string[] = [];
  // Random per test-run octet so re-running this suite (or a prior crashed
  // run's leftovers) can't collide with scan_excludes_global_unique.
  const octet = crypto.randomInt(1, 250);
  const globalIp = `10.99.${octet}.1`;
  const scopedIp = `10.99.${octet}.2`;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    agentA = await createTestAgent("it-agent-a");
    agentB = await createTestAgent("it-agent-b");
  });

  afterAll(async () => {
    for (const id of excludeIds) {
      await db.deleteFrom("scan_excludes").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
    await deleteTestAgent(agentA.id);
    await deleteTestAgent(agentB.id);
    // No closeDb() here - closeDb() ends the whole shared pg pool, and
    // this file has a second describe block below that still needs it.
    // Only the last describe block in the file calls closeDb().
  });

  it("gives every scanner the global exclude, but only the scoped agent its own", async () => {
    const client = await loginAs(admin.username, admin.password);

    const globalRes = await client.post("/api/excludes").send({ kind: "ip", value: globalIp });
    expect(globalRes.status).toBe(201);
    excludeIds.push(globalRes.body.id);

    const scopedRes = await client
      .post("/api/excludes")
      .send({ kind: "ip", value: scopedIp, scannerAgentId: agentA.id });
    expect(scopedRes.status).toBe(201);
    excludeIds.push(scopedRes.body.id);

    const asA = await request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${agentA.apiKey}`);
    expect(asA.status).toBe(200);
    expect((asA.body as ExcludesResponse).ips.slice().sort()).toEqual([globalIp, scopedIp].sort());

    const asB = await request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${agentB.apiKey}`);
    expect(asB.status).toBe(200);
    expect((asB.body as ExcludesResponse).ips).toEqual([globalIp]);
  });
});

// masscan has no IPv6 capability, so IPv6 targets are discovered via nmap
// directly (see scanner's ipv6.go/RunNmapDiscovery) - there's no
// --excludefile step in that path, so the scanner checks IP/CIDR excludes
// itself (isTargetExcluded), and ip_port excludes need bracket notation
// ("[ipv6]:port") since an IPv6 address itself contains colons, unlike
// IPv4. This covers the webserver-side validation and the GET /excludes
// reconstruction the scanner actually consumes.
describe("IPv6 scan excludes", () => {
  let admin: TestUser;
  let agent: TestAgent;
  const excludeIds: string[] = [];

  beforeAll(async () => {
    admin = await createTestUser("admin");
    agent = await createTestAgent("it-ipv6-agent");
  });

  afterAll(async () => {
    for (const id of excludeIds) {
      await db.deleteFrom("scan_excludes").where("id", "=", id).execute();
    }
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("accepts a single IPv6 address and an IPv6 CIDR as 'ip' excludes", async () => {
    const client = await loginAs(admin.username, admin.password);

    const single = await client.post("/api/excludes").send({ kind: "ip", value: "2001:db8::99" });
    expect(single.status).toBe(201);
    excludeIds.push(single.body.id);

    const cidr = await client.post("/api/excludes").send({ kind: "ip", value: "2001:db8:1::/64" });
    expect(cidr.status).toBe(201);
    excludeIds.push(cidr.body.id);

    const res = await request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${agent.apiKey}`);
    expect(res.status).toBe(200);
    expect((res.body as ExcludesResponse).ips.sort()).toEqual(["2001:db8:1::/64", "2001:db8::99"].sort());
  });

  it("rejects an IPv6 'start-end' range - only addresses and CIDRs are supported", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.post("/api/excludes").send({ kind: "ip", value: "2001:db8::1-2001:db8::10" });
    expect(res.status).toBe(400);
  });

  it("accepts a bracket-notation ip_port exclude and reconstructs ip/portSpec correctly", async () => {
    const client = await loginAs(admin.username, admin.password);

    const res = await client.post("/api/excludes").send({ kind: "ip_port", value: "[2001:db8::1]:3389" });
    expect(res.status).toBe(201);
    excludeIds.push(res.body.id);

    const ingestRes = await request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${agent.apiKey}`);
    expect(ingestRes.status).toBe(200);
    const ipPorts = (ingestRes.body as ExcludesResponse).ipPorts;
    expect(ipPorts).toContainEqual({ ip: "2001:db8::1", portSpec: "3389" });
  });

  it("rejects an ip_port value with an unbracketed IPv6 address", async () => {
    const client = await loginAs(admin.username, admin.password);
    const res = await client.post("/api/excludes").send({ kind: "ip_port", value: "2001:db8::1:3389" });
    expect(res.status).toBe(400);
  });
});
