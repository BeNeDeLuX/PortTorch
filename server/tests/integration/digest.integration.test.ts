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

// Class E (240.0.0.0/4) - reserved, never a real target, so it can't
// collide with genuine data even run against a copy of a real database.
const NEW_HOST_IP = "240.2.1.1";
const CHANGED_HOST_IP = "240.2.1.2";

// Digest entries used to have no timestamp or scanner name at all - a
// user reported both were missing. This covers that both fields are
// present and correct for a genuinely new host and for a host with a
// port change, for the scanner that actually reported them.
describe("digest includes observedAt/scannerAgentName per host", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  const windowFrom = new Date(Date.now() - 60_000).toISOString();

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-digest-agent");

    // Host A: a single scan - shows up as a newly discovered host.
    const jobA = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: NEW_HOST_IP, portSpec: "22" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobA.body.id,
        hosts: [{ ip: NEW_HOST_IP, ports: [{ port: 22, protocol: "tcp", state: "open" }] }],
      });

    // Host B: two scans, port 22 -> port 80 - shows up as a port change.
    const jobB1 = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: CHANGED_HOST_IP, portSpec: "22" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobB1.body.id,
        hosts: [{ ip: CHANGED_HOST_IP, ports: [{ port: 22, protocol: "tcp", state: "open" }] }],
      });
    const jobB2 = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: CHANGED_HOST_IP, portSpec: "80" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobB2.body.id,
        hosts: [
          {
            ip: CHANGED_HOST_IP,
            ports: [
              { port: 22, protocol: "tcp", state: "closed" },
              { port: 80, protocol: "tcp", state: "open" },
            ],
          },
        ],
      });
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("ip", "in", [NEW_HOST_IP, CHANGED_HOST_IP]).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("includes observedAt and scannerAgentName for a newly discovered host", async () => {
    const res = await client.get(`/api/digest?from=${encodeURIComponent(windowFrom)}`);
    expect(res.status).toBe(200);
    const entry = res.body.newHosts.find((h: { ip: string }) => h.ip === NEW_HOST_IP);
    expect(entry).toBeDefined();
    expect(entry.scannerAgentName).toBe(agent.name);
    expect(new Date(entry.observedAt).getTime()).toBeGreaterThan(Date.now() - 60_000);
  });

  it("includes observedAt and scannerAgentName for a host with a port change", async () => {
    const res = await client.get(`/api/digest?from=${encodeURIComponent(windowFrom)}`);
    expect(res.status).toBe(200);
    const entry = res.body.changedHosts.find((h: { ip: string }) => h.ip === CHANGED_HOST_IP);
    expect(entry).toBeDefined();
    expect(entry.scannerAgentName).toBe(agent.name);
    expect(new Date(entry.observedAt).getTime()).toBeGreaterThan(Date.now() - 60_000);
    expect(entry.newlyOpen.map((p: { port: number }) => p.port)).toEqual([80]);
  });
});
