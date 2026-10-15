import http from "http";
import type { AddressInfo } from "net";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { checkResourcePressure } from "../../src/scannerMetrics/metrics";
import { checkWebserverDisk } from "../../src/webserverStorage/storage";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, getApp, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

const MIN = 60_000;
const DAY = 86_400_000;

const sample = (at: Date, over: Record<string, number> = {}) => ({
  at: at.toISOString(),
  cpuPercent: 20,
  memUsedBytes: 2 * 1024 ** 3,
  memTotalBytes: 8 * 1024 ** 3,
  netRxBytesPerSec: 1000,
  netTxBytesPerSec: 500,
  load1: 0.5,
  scansRunning: 0,
  ...over,
});

describe("load thresholds, overloaded scans, webserver storage, estimates and device uptime", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; data: Record<string, unknown> }> = [];
  let webhookId: string;

  const ingest = (path: string, body: unknown, method: "post" | "patch" = "post") =>
    request(getApp())[method](`/api/ingest${path}`).set("Authorization", `Bearer ${agent.apiKey}`).send(body as object);
  const settle = () => new Promise((r) => setTimeout(r, 300));

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
          name: `it-load-${Date.now()}`,
          channel_type: "webhook",
          url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`,
          events: ["scanner.resource_pressure", "webserver.disk_low", "device.rebooted"],
          enabled: true,
        })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;
    agent = await createTestAgent("it-load");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    await client.patch("/api/settings/app").send({ cpuAlertPercent: 90, memAlertPercent: 90, diskLowPercent: 10 });
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("hosts").where("scanner_agent_id", "=", agent.id).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    server.close();
    await closeDb();
  });

  it("alerts on load against the admin's threshold, not a constant", async () => {
    const now = new Date();
    await ingest("/metrics", { samples: Array.from({ length: 12 }, (_, i) => sample(new Date(now.getTime() - (i + 1) * MIN), { cpuPercent: 70 })) });
    received = [];
    await checkResourcePressure(now);
    await settle();
    expect(received.filter((r) => r.data.scanner_agent_id === agent.id)).toHaveLength(0);

    // 70% is under the default 90 and over a configured 60.
    expect((await client.patch("/api/settings/app").send({ cpuAlertPercent: 60 })).status).toBe(200);
    expect((await client.get("/api/settings/app")).body.cpuAlertPercent).toBe(60);
    await checkResourcePressure(now);
    await settle();
    expect(received.filter((r) => r.data.scanner_agent_id === agent.id)).toHaveLength(1);
    expect((await client.patch("/api/settings/app").send({ diskLowPercent: 70 })).status).toBe(400);
  });

  it("flags a scan that ran on an overloaded host", async () => {
    await client.patch("/api/settings/app").send({ cpuAlertPercent: 90 });
    // Only this test's samples in the scan window - the share is the point.
    await db.deleteFrom("scanner_metrics").where("scanner_agent_id", "=", agent.id).execute();
    const job = (await ingest("/scan-jobs", { targetSpec: "198.51.100.0/24", portSpec: "22" })).body.id as string;
    const start = (await db.selectFrom("scan_jobs").select("started_at").where("id", "=", job).executeTakeFirstOrThrow()).started_at;
    // Six samples in the scan, four of them pinned.
    await db.updateTable("scan_jobs").set({ started_at: new Date(start.getTime() - 10 * MIN) }).where("id", "=", job).execute();
    await ingest("/metrics", {
      samples: [95, 97, 99, 96, 30, 20].map((cpu, i) => sample(new Date(start.getTime() - (9 - i) * MIN), { cpuPercent: cpu })),
    });
    expect((await ingest(`/scan-jobs/${job}`, { status: "completed" }, "patch")).status).toBe(204);
    const row = await db.selectFrom("scan_jobs").select("anomalies").where("id", "=", job).executeTakeFirstOrThrow();
    const saturated = (row.anomalies as Array<{ kind: string; share: number; peakCpu: number }>).find((a) => a.kind === "host_saturated");
    expect(saturated).toMatchObject({ peakCpu: 99 });
    expect(saturated!.share).toBeGreaterThanOrEqual(0.5);
  });

  it("reports the webserver's own disk and database, and alerts once below the line", async () => {
    const res = await client.get("/api/settings/webserver-storage");
    expect(res.status).toBe(200);
    expect(res.body.dbBytes).toBeGreaterThan(0);
    expect(res.body.diskTotalBytes).toBeGreaterThan(0);
    expect(res.body.diskLow).toBe(res.body.diskFreePercent < res.body.diskLowPercent);

    // The line at 50% free: whichever side this machine's disk is on,
    // the alert must agree with it and fire at most once.
    await client.patch("/api/settings/app").send({ diskLowPercent: 50 });
    await db.updateTable("app_settings").set({ webserver_disk_alert_sent_at: null }).where("id", "=", 1).execute();
    received = [];
    const first = await checkWebserverDisk();
    const second = await checkWebserverDisk();
    await settle();
    const below = (await client.get("/api/settings/webserver-storage")).body.diskFreePercent < 50;
    expect(first).toBe(below);
    expect(second).toBe(false);
    expect(received.filter((r) => r.event === "webserver.disk_low")).toHaveLength(below ? 1 : 0);
    const day = new Date().toISOString().slice(0, 10);
    expect((await db.selectFrom("webserver_storage_samples").select("day").execute()).some((r) => new Date(r.day).toISOString().slice(0, 10) === day)).toBe(true);
    // Not readable by a non-admin.
    const user = await createTestUser("operator");
    try {
      expect((await (await loginAs(user.username, user.password)).get("/api/settings/webserver-storage")).status).toBe(403);
    } finally {
      await deleteTestUser(user.id);
    }
  });

  it("projects the rest of a scan from this scanner's history", async () => {
    // Three earlier /24 scans of port 22, each confirming 4 hosts.
    for (let n = 0; n < 3; n++) {
      const started = new Date(Date.now() - (n + 2) * DAY);
      const job = await db
        .insertInto("scan_jobs")
        .values({ scanner_agent_id: agent.id, target_spec: `203.0.113.0/24`, port_spec: "22", status: "completed", started_at: started, finished_at: new Date(started.getTime() + 60_000) })
        .returning("id")
        .executeTakeFirstOrThrow();
      for (let h = 1; h <= 4; h++) {
        const host = await db
          .insertInto("hosts")
          .values({ ip: `203.0.113.${n * 10 + h}`, scanner_agent_id: agent.id } as never)
          .onConflict((oc) => oc.columns(["ip", "scanner_agent_id"]).doUpdateSet({ last_seen_at: new Date() }))
          .returning("id")
          .executeTakeFirstOrThrow();
        await db.insertInto("host_port_observations").values({ host_id: host.id, scan_job_id: job.id, port: 22, protocol: "tcp", state: "open" } as never).execute();
      }
    }
    const res = await client.post("/api/scan-estimate").send({ targetSpec: "203.0.113.0/23", portSpec: "22", scannerAgentId: agent.id });
    expect(res.status).toBe(200);
    expect(res.body.enrichment.basedOnScans).toBeGreaterThanOrEqual(3);
    expect(res.body.enrichment.expectedHosts).toBeGreaterThan(0);
    expect(res.body.enrichment.enrichmentSeconds).toBeGreaterThan(0);
  });

  it("stores a device's uptime from SNMP and reports a reboot", async () => {
    const snmpPort = (scripts: Array<{ id: string; output: string }>) => ({ port: 161, protocol: "udp", state: "open", serviceName: "snmp", extraScripts: scripts });
    const engine = (boots: number, time: string) => ({ id: "snmp-info", output: `\n  enterprise: ciscoSystems\n  engineIDFormat: mac\n  engineIDData: 00:d4:78:9b:c0:c7\n  snmpEngineBoots: ${boots}\n  snmpEngineTime: ${time}` });
    const submit = async (ip: string, scripts: Array<{ id: string; output: string }>) => {
      const job = (await ingest("/scan-jobs", { targetSpec: ip, portSpec: "U:161" })).body.id;
      expect((await ingest("/hosts", { scanJobId: job, hosts: [{ ip, ports: [snmpPort(scripts)] }] })).status).toBe(204);
    };
    const host = (ip: string) =>
      db.selectFrom("hosts").select(["boot_time", "uptime_source", "snmp_engine_boots"]).where("ip", "=", ip).where("scanner_agent_id", "=", agent.id).executeTakeFirstOrThrow();

    await submit("198.51.100.50", [engine(110, "412d03h56m16s")]);
    const first = await host("198.51.100.50");
    expect(first.uptime_source).toBe("snmp-engine");
    expect(first.snmp_engine_boots).toBe(110);
    expect(Math.round((Date.now() - first.boot_time!.getTime()) / DAY)).toBe(412);
    const detail = await client.get(`/api/hosts?q=198.51.100.50`);
    expect(detail.body.items[0].boot_time).not.toBeNull();

    received = [];
    await submit("198.51.100.50", [engine(110, "412d04h10m00s")]);
    await submit("198.51.100.50", [engine(111, "0d00h05m00s")]);
    await settle();
    const reboots = received.filter((r) => r.event === "device.rebooted" && r.data.ip === "198.51.100.50");
    expect(reboots).toHaveLength(1);
    expect((await host("198.51.100.50")).snmp_engine_boots).toBe(111);

    // sysUpTime only: a reset is a reboot too.
    const sys = (ticks: number) => ({ id: "snmp-sysdescr", output: `Switch\n  System uptime: x (${ticks} timeticks)` });
    await submit("198.51.100.51", [sys(40 * 8_640_000)]);
    received = [];
    await submit("198.51.100.51", [sys(360_000)]);
    await settle();
    expect(received.filter((r) => r.event === "device.rebooted" && r.data.ip === "198.51.100.51")).toHaveLength(1);
    expect((await host("198.51.100.51")).uptime_source).toBe("snmp-sysuptime");
  });
});
