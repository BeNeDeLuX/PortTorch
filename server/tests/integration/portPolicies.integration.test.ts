import http from "http";
import type { AddressInfo } from "net";
import { sql } from "kysely";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { checkPortPolicies } from "../../src/portPolicies/evaluate";
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

// "In this network only these ports" / "never these ports", evaluated
// against the current port state and alerted once per violation.
describe("port policies", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let admin: TestUser;
  let operator: TestUser;
  let restricted: TestUser;
  let adminClient: SessionClient;
  let op: SessionClient;
  let restrictedClient: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; data: Record<string, unknown> }> = [];
  let webhookId: string;
  let jobId: string;
  const hostIds: Record<string, string> = {};

  async function host(ip: string, ports: Array<[number, string, string?]>, a: TestAgent = agent) {
    const row = await db.insertInto("hosts").values({ ip, scanner_agent_id: a.id }).returning("id").executeTakeFirstOrThrow();
    hostIds[ip] = row.id;
    for (const [port, protocol, state] of ports) {
      await db
        .insertInto("host_port_observations")
        .values({ host_id: row.id, scan_job_id: jobId, port, protocol, state: state ?? "open", service_name: `svc${port}` })
        .execute();
    }
  }

  async function waitForDeliveries(count: number) {
    for (let i = 0; i < 50 && received.length < count; i++) await new Promise((r) => setTimeout(r, 50));
  }

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.writeHead(200).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    webhookId = (
      await db
        .insertInto("webhooks")
        .values({
          name: `it-policy-${Date.now()}`,
          channel_type: "webhook",
          url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`,
          events: ["port_policy.violation"],
          enabled: true,
        })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;

    agent = await createTestAgent("it-policy");
    other = await createTestAgent("it-policy-other");
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: other.id }).execute();
    adminClient = await loginAs(admin.username, admin.password);
    op = await loginAs(operator.username, operator.password);
    restrictedClient = await loginAs(restricted.username, restricted.password);

    jobId = (
      await request(getApp()).post("/api/ingest/scan-jobs").set("Authorization", `Bearer ${agent.apiKey}`).send({ targetSpec: "10.95.0.0/24", portSpec: "1-65535" })
    ).body.id;
    // A web server, one with RDP open, one where 3389 was seen open and
    // later recorded closed, and a DNS server on UDP.
    await host("10.95.0.1", [[22, "tcp"], [443, "tcp"]]);
    await host("10.95.0.2", [[443, "tcp"], [3389, "tcp"]]);
    await host("10.95.0.3", [[443, "tcp"]]);
    await db
      .insertInto("host_port_observations")
      .values([
        { host_id: hostIds["10.95.0.3"], scan_job_id: jobId, port: 3389, protocol: "tcp", state: "open", observed_at: new Date(Date.now() - 60_000).toISOString() },
        { host_id: hostIds["10.95.0.3"], scan_job_id: jobId, port: 3389, protocol: "tcp", state: "closed", observed_at: new Date().toISOString() },
      ])
      .execute();
    await host("10.95.0.4", [[53, "udp"], [53, "tcp"]]);
    // Outside the network, and on a scanner the restricted user may see.
    await host("10.95.1.1", [[3389, "tcp"]]);
    await host("10.95.0.9", [[3389, "tcp"]], other);
  });

  afterAll(async () => {
    await db.deleteFrom("port_policies").where(sql<boolean>`network <<= '10.95.0.0/16'::cidr`).execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("hosts").where("id", "in", Object.values(hostIds)).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    for (const u of [admin, operator, restricted]) await deleteTestUser(u.id);
    server.close();
    await closeDb();
  });

  let denyRdp: string;
  let dmzOnly: string;

  it("is admin-only to write, and refuses a policy it could not evaluate", async () => {
    expect((await op.post("/api/port-policies").send({ name: "x", network: "10.95.0", mode: "deny", ports: "3389" })).status).toBe(403);
    expect((await adminClient.post("/api/port-policies").send({ name: "x", network: "10.95.0", mode: "deny", ports: "rdp" })).status).toBe(400);
    expect((await adminClient.post("/api/port-policies").send({ name: "x", network: "intranet", mode: "deny", ports: "3389" })).status).toBe(400);

    const deny = await adminClient.post("/api/port-policies").send({ name: "No RDP", network: "10.95.0", mode: "deny", ports: "3389" });
    expect(deny.status).toBe(201);
    expect(deny.body.network).toBe("10.95.0.0/24");
    denyRdp = deny.body.id;
    dmzOnly = (await adminClient.post("/api/port-policies").send({ name: "DMZ", network: "10.95.0.0/24", mode: "allow", ports: "22,443,U:53", scannerAgentId: agent.id })).body.id;
  });

  it("finds what a deny policy forbids and an allow policy does not list", async () => {
    const deny = await op.get(`/api/port-policies/${denyRdp}`);
    // .3's 3389 was recorded closed afterwards, so it no longer violates;
    // .9 is in the network on the other scanner; .1.1 is outside it.
    expect(deny.body.violations.items.map((v: { ip: string; port: number }) => `${v.ip}:${v.port}`)).toEqual([
      "10.95.0.2:3389",
      "10.95.0.9:3389",
    ]);

    const allow = await op.get(`/api/port-policies/${dmzOnly}`);
    // UDP/53 is listed, TCP/53 is not - protocol is part of the rule.
    expect(allow.body.violations.items.map((v: { ip: string; port: number; protocol: string }) => `${v.ip}:${v.port}/${v.protocol}`)).toEqual([
      "10.95.0.2:3389/tcp",
      "10.95.0.4:53/tcp",
    ]);

    const list = (await op.get("/api/port-policies")).body;
    expect(list.find((p: { id: string }) => p.id === dmzOnly)).toMatchObject({ violations: 2, violatingHosts: 2, mode: "allow" });
  });

  it("alerts once per violation, and again only for new ones", async () => {
    received = [];
    await checkPortPolicies();
    await waitForDeliveries(2);
    const forDeny = received.filter((r) => r.data.policy_id === denyRdp);
    expect(forDeny).toHaveLength(1);
    expect((forDeny[0].data.violations as Array<{ ip: string }>).map((v) => v.ip)).toEqual(["10.95.0.2", "10.95.0.9"]);

    received = [];
    await checkPortPolicies();
    await new Promise((r) => setTimeout(r, 300));
    expect(received.filter((r) => [denyRdp, dmzOnly].includes(r.data.policy_id as string))).toHaveLength(0);

    await db.insertInto("host_port_observations").values({ host_id: hostIds["10.95.0.1"], scan_job_id: jobId, port: 3389, protocol: "tcp", state: "open" }).execute();
    received = [];
    await checkPortPolicies();
    await waitForDeliveries(2);
    const next = received.filter((r) => r.data.policy_id === denyRdp);
    expect(next).toHaveLength(1);
    expect((next[0].data.violations as Array<{ ip: string }>).map((v) => v.ip)).toEqual(["10.95.0.1"]);
  });

  it("starts the reporting over when the rule itself changes, and stays quiet when disabled", async () => {
    expect((await adminClient.patch(`/api/port-policies/${denyRdp}`).send({ ports: "3389,22" })).status).toBe(204);
    const row = await db.selectFrom("port_policies").select("alerted_keys").where("id", "=", denyRdp).executeTakeFirstOrThrow();
    expect(row.alerted_keys).toEqual([]);

    expect((await adminClient.patch(`/api/port-policies/${denyRdp}`).send({ enabled: false })).status).toBe(204);
    received = [];
    await checkPortPolicies();
    await new Promise((r) => setTimeout(r, 300));
    expect(received.filter((r) => r.data.policy_id === denyRdp)).toHaveLength(0);
    expect((await adminClient.patch(`/api/port-policies/${denyRdp}`).send({})).status).toBe(400);
  });

  it("keeps a restricted session to its own scanners", async () => {
    const visible = (await restrictedClient.get("/api/port-policies")).body.map((p: { id: string }) => p.id);
    expect(visible).toContain(denyRdp);
    // Scoped to a scanner it cannot see: invisible.
    expect(visible).not.toContain(dmzOnly);
    expect((await restrictedClient.get(`/api/port-policies/${dmzOnly}`)).status).toBe(404);
    // A global policy's violations narrowed to its own scanner.
    const deny = await restrictedClient.get(`/api/port-policies/${denyRdp}`);
    expect(deny.body.violations.items.map((v: { ip: string }) => v.ip)).toEqual(["10.95.0.9"]);
  });

  it("deletes", async () => {
    expect((await op.delete(`/api/port-policies/${dmzOnly}`)).status).toBe(403);
    expect((await adminClient.delete(`/api/port-policies/${dmzOnly}`)).status).toBe(204);
    expect((await adminClient.get(`/api/port-policies/${dmzOnly}`)).status).toBe(404);
  });
});
