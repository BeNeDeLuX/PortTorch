import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

// Class E (240.0.0.0/4) - reserved, never a real target, so it can't
// collide with genuine data even run against a copy of a real database.
const IP = "240.5.1.1";

// Covers the CSV export's two row-shape modes (?detail=host, the default
// "1 row per host" summary vs ?detail=port, "1 row per host+open-port" for
// a flat asset-inventory export) - both must reflect the exact same
// filtered set of hosts, just at a different grain.
describe("hosts CSV export - host vs port detail", () => {
  let admin: TestUser;
  let client: SessionClient;
  let agent: TestAgent;
  let hostId: string;

  beforeAll(async () => {
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
    agent = await createTestAgent("it-export-agent");

    const jobRes = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "22,443" });

    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: jobRes.body.id,
        hosts: [
          {
            ip: IP,
            hostname: "it-export-host",
            ports: [
              { port: 22, protocol: "tcp", state: "open", serviceName: "ssh" },
              { port: 443, protocol: "tcp", state: "open", serviceName: "https" },
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

  it("defaults to one summary row per host with open_port_count", async () => {
    const res = await client.get("/api/hosts/export.csv").query({ q: IP });
    expect(res.status).toBe(200);
    const lines = res.text.trim().split("\r\n");
    expect(lines[0]).toBe("ip,hostname,scanner_agent,os_family,device_type,mac_address,mac_vendor,open_port_count,last_seen_at");
    const row = lines.find((l) => l.startsWith(IP));
    expect(row).toBeDefined();
    expect(row).toContain(`${IP},it-export-host,${agent.name},,,,,2,`);
  });

  it("detail=host is equivalent to the default", async () => {
    const res = await client.get("/api/hosts/export.csv").query({ q: IP, detail: "host" });
    expect(res.status).toBe(200);
    expect(res.text.split("\r\n")[0]).toBe("ip,hostname,scanner_agent,os_family,device_type,mac_address,mac_vendor,open_port_count,last_seen_at");
  });

  it("detail=port returns one row per open port instead", async () => {
    const res = await client.get("/api/hosts/export.csv").query({ q: IP, detail: "port" });
    expect(res.status).toBe(200);
    const lines = res.text.trim().split("\r\n");
    expect(lines[0]).toBe(
      "ip,hostname,scanner_agent,os_family,device_type,mac_address,mac_vendor,port,protocol,service_name,service_product,service_version,last_seen_at"
    );
    const dataLines = lines.slice(1);
    expect(dataLines).toHaveLength(2);
    expect(dataLines.some((l) => l.startsWith(`${IP},it-export-host,${agent.name},,,,,22,tcp,ssh`))).toBe(true);
    expect(dataLines.some((l) => l.startsWith(`${IP},it-export-host,${agent.name},,,,,443,tcp,https`))).toBe(true);
  });

  it("an unrecognized detail value falls back to the host summary shape", async () => {
    const res = await client.get("/api/hosts/export.csv").query({ q: IP, detail: "bogus" });
    expect(res.status).toBe(200);
    expect(res.text.split("\r\n")[0]).toBe("ip,hostname,scanner_agent,os_family,device_type,mac_address,mac_vendor,open_port_count,last_seen_at");
  });

  it("export.json returns one object per host with a nested openPorts list", async () => {
    const res = await client.get("/api/hosts/export.json").query({ q: IP });
    expect(res.status).toBe(200);
    const rows = res.body as Array<{ ip: string; hostname: string | null; scannerAgent: string | null; openPorts: Array<{ port: number; serviceName: string | null }> }>;
    const row = rows.find((r) => r.ip === IP);
    expect(row).toBeDefined();
    expect(row?.hostname).toBe("it-export-host");
    expect(row?.scannerAgent).toBe(agent.name);
    expect(row?.openPorts).toHaveLength(2);
    expect(row?.openPorts.some((p) => p.port === 22 && p.serviceName === "ssh")).toBe(true);
    expect(row?.openPorts.some((p) => p.port === 443 && p.serviceName === "https")).toBe(true);
  });
});
