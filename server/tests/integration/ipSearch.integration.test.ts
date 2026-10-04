import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { sql } from "kysely";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// The explicit `ip:` search: addresses only, and a partly typed IPv4
// address names its block. The plain search never matched an address
// prefix at all - typing 10.20.41 found nothing - and is left that way on
// purpose, since saved searches and the External API run it too.
describe("dashboard ip: search", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;

  async function ingest(ip: string, hostname?: string) {
    const job = await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${agent.apiKey}`).send({ targetSpec: ip, portSpec: "22" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ scanJobId: job.body.id, hosts: [{ ip, ...(hostname ? { hostname } : {}), ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] }] });
  }

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-ip-search");
    await ingest("240.92.5.7");
    // A hostname containing another block's digits: the plain search
    // matches it by text, an ip: search must not.
    await ingest("240.92.6.8", "legacy-240.92.5.box");
    await ingest("2001:db8:92::1");
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip <<= '240.92.0.0/16'::cidr OR ip = '2001:db8:92::1'::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function ips(q: string): Promise<string[]> {
    const res = await client.get(`/api/hosts?q=${encodeURIComponent(q)}&pageSize=200`);
    expect(res.status).toBe(200);
    return (res.body.items as Array<{ ip: string }>).map((h) => h.ip).filter((ip) => ip.startsWith("240.92.") || ip.startsWith("2001:db8:92:")).sort();
  }

  it("reads a partly typed IPv4 address as its block, and matches addresses only", async () => {
    expect(await ips("ip:240.92.5")).toEqual(["240.92.5.7"]);
    expect(await ips("ip:240.92")).toEqual(["240.92.5.7", "240.92.6.8"]);
    expect(await ips("IP: 240.92.6.")).toEqual(["240.92.6.8"]);
    // The plain search matches the hostname's text, which is exactly why
    // the address search is its own syntax.
    expect(await ips("240.92.5")).toEqual(["240.92.6.8"]);
  });

  it("takes exact addresses, CIDRs and IPv6 prefixes", async () => {
    expect(await ips("ip:240.92.6.8")).toEqual(["240.92.6.8"]);
    expect(await ips("ip:240.92.5.0/24")).toEqual(["240.92.5.7"]);
    expect(await ips("ip:2001:db8:92:")).toEqual(["2001:db8:92::1"]);
  });

  it("matches nothing for a value that cannot be an address", async () => {
    expect(await ips("ip:ssh")).toEqual([]);
  });

  it("scopes the facets the same way as the list", async () => {
    const res = await client.get(`/api/hosts/facets?q=${encodeURIComponent("ip:240.92.5")}`);
    expect(res.status).toBe(200);
    const ssh = res.body.services.find((s: { service: string }) => s.service === "ssh");
    expect(ssh?.count).toBe(1);
  });
});
