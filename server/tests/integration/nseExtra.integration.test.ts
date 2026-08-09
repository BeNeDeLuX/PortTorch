import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target.
const IP = "240.6.5.1";
const MONGO_OUTPUT = "ok: 1.0\ndatabases\n  admin\n  config\n  customer-export-db";
const NFS_OUTPUT = "Mount requests:\n  /export/backups\n    Allowed clients: 10.0.0.0/8";

describe("Generic NSE extra-script capture (nse_extra jsonb - nfs-showmount, mongodb-databases, etc.)", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let hostId: string;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-nse-extra-agent");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "111,27017" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            ip: IP,
            hostname: "it-nse-extra-host",
            ports: [
              {
                port: 111,
                protocol: "tcp",
                state: "open",
                serviceName: "rpcbind",
                extraScripts: [{ id: "nfs-showmount", output: NFS_OUTPUT }],
              },
              {
                port: 27017,
                protocol: "tcp",
                state: "open",
                serviceName: "mongod",
                extraScripts: [{ id: "mongodb-databases", output: MONGO_OUTPUT }],
              },
            ],
          },
        ],
      });

    const hostRow = await db.selectFrom("hosts").select(["id"]).where("ip", "=", IP).executeTakeFirstOrThrow();
    hostId = hostRow.id;
  });

  afterAll(async () => {
    await db.deleteFrom("hosts").where("id", "=", hostId).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  it("GET /api/hosts/:id returns each port's own nse_extra entries, not mixed up between ports", async () => {
    const res = await client.get(`/api/hosts/${hostId}`);
    expect(res.status).toBe(200);

    const ports = res.body.ports as Array<{ port: number; nse_extra: Array<{ id: string; output: string }> | null }>;
    const rpcPort = ports.find((p) => p.port === 111);
    const mongoPort = ports.find((p) => p.port === 27017);

    expect(rpcPort?.nse_extra).toEqual([{ id: "nfs-showmount", output: NFS_OUTPUT }]);
    expect(mongoPort?.nse_extra).toEqual([{ id: "mongodb-databases", output: MONGO_OUTPUT }]);
  });

  it("free-text search matches text inside an nse_extra script's output", async () => {
    const res = await client.get("/api/hosts").query({ q: "customer-export-db" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(true);
  });

  it("free-text search matches an NFS export path from a different port's nse_extra entry", async () => {
    const res = await client.get("/api/hosts").query({ q: "export/backups" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(true);
  });

  it("free-text search for an unrelated term does not match", async () => {
    const res = await client.get("/api/hosts").query({ q: "no-such-term-anywhere-xyz" });
    expect(res.status).toBe(200);
    expect((res.body.items as Array<{ id: string }>).some((h) => h.id === hostId)).toBe(false);
  });
});
