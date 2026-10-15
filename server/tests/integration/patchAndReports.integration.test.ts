import http from "http";
import type { AddressInfo } from "net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { flushBundles } from "../../src/webhooks/bundle";
import { dispatchWebhook } from "../../src/webhooks/dispatch";
import { computeWeeklyReport, weeklyTick } from "../../src/digest/weeklyReport";
import { closeDb, createTestAgent, createTestUser, deleteTestAgent, deleteTestUser, loginAs, type SessionClient, type TestAgent, type TestUser } from "./helpers";

const DAY = 86_400_000;

describe("uptime filter, SNMP firmware, patch priority, run comparison, alert bundling, weekly report", () => {
  let agent: TestAgent;
  let other: TestAgent;
  let admin: TestUser;
  let restricted: TestUser;
  let client: SessionClient;
  let restrictedClient: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; text: string; data: Record<string, unknown> }> = [];
  let hookUrl: string;
  const hostIds: Record<string, string> = {};

  const sysdescr = (line: string) => JSON.stringify([{ id: "snmp-sysdescr", output: `${line}\n  System uptime: 1d (8640000 timeticks)` }]);

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
    hookUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
    agent = await createTestAgent("it-patch");
    other = await createTestAgent("it-patch-other");
    admin = await createTestUser("admin");
    restricted = await createTestUser("operator");
    await db.insertInto("user_scanner_agents").values({ user_id: restricted.id, scanner_agent_id: other.id }).execute();
    client = await loginAs(admin.username, admin.password);
    restrictedClient = await loginAs(restricted.username, restricted.password);

    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: "198.18.0.0/24", port_spec: "22,U:161", status: "completed", finished_at: new Date() })
      .returning("id")
      .executeTakeFirstOrThrow();
    const add = async (ip: string, bootDaysAgo: number | null, firmware: string | null) => {
      const h = await db
        .insertInto("hosts")
        .values({ ip, scanner_agent_id: agent.id, boot_time: bootDaysAgo === null ? null : new Date(Date.now() - bootDaysAgo * DAY), uptime_source: bootDaysAgo === null ? null : "snmp-engine" } as never)
        .returning("id")
        .executeTakeFirstOrThrow();
      hostIds[ip] = h.id;
      await db.insertInto("host_port_observations").values({ host_id: h.id, scan_job_id: job.id, port: 22, protocol: "tcp", state: "open", service_name: "ssh" } as never).execute();
      if (firmware) {
        await db
          .insertInto("host_port_observations")
          .values({ host_id: h.id, scan_job_id: job.id, port: 161, protocol: "udp", state: "open", service_name: "snmp", nse_extra: sysdescr(firmware) } as never)
          .execute();
      }
    };
    await add("198.18.0.1", 400, "ITSwitch-48, 7.5.10.17129");
    await add("198.18.0.2", 10, "ITSwitch-48, 7.5.15.17146");
    await add("198.18.0.3", null, null);
  });

  afterAll(async () => {
    await db.deleteFrom("webhooks").where("name", "like", "it-patch-%").execute();
    await db.deleteFrom("hosts").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await db.deleteFrom("scan_requests").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await db.deleteFrom("scan_schedules").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "in", [agent.id, other.id]).execute();
    await deleteTestAgent(agent.id);
    await deleteTestAgent(other.id);
    await deleteTestUser(admin.id);
    await deleteTestUser(restricted.id);
    server.close();
    await closeDb();
  });

  it("filters hosts by uptime, and never matches an unknown one", async () => {
    const res = await client.get(`/api/hosts?minUptimeDays=180&scannerAgentId=${agent.id}`);
    expect(res.body.items.map((h: { ip: string }) => h.ip)).toEqual(["198.18.0.1"]);
    const all = await client.get(`/api/hosts?minUptimeDays=1&scannerAgentId=${agent.id}`);
    expect(all.body.items.map((h: { ip: string }) => h.ip).sort()).toEqual(["198.18.0.1", "198.18.0.2"]);
  });

  it("lists SNMP firmware in the software inventory and marks the older version", async () => {
    const res = await client.get("/api/software");
    const rows = res.body.items.filter((r: { product: string }) => r.product === "ITSwitch-48");
    expect(rows).toHaveLength(2);
    const older = rows.find((r: { version: string }) => r.version === "7.5.10.17129");
    const newer = rows.find((r: { version: string }) => r.version === "7.5.15.17146");
    expect(older).toMatchObject({ sources: ["snmp"], hosts: 1, newerInFleet: "7.5.15.17146" });
    expect(newer.newerInFleet).toBeNull();
  });

  it("serves patch-priority signals, scoped to the session's scanners", async () => {
    const res = await client.get("/api/patch-priority");
    const mine = res.body.items.filter((h: { ip: string }) => h.ip.startsWith("198.18.0."));
    const old = mine.find((h: { ip: string }) => h.ip === "198.18.0.1");
    expect(old.bootTime).not.toBeNull();
    expect(old.software.find((s: { source: string }) => s.source === "snmp")).toMatchObject({ product: "ITSwitch-48", newerInFleet: "7.5.15.17146" });
    // A host with no signal at all is not listed.
    expect(mine.find((h: { ip: string }) => h.ip === "198.18.0.3")).toBeUndefined();
    const scoped = await restrictedClient.get("/api/patch-priority");
    expect(scoped.body.items.some((h: { ip: string }) => h.ip.startsWith("198.18.0."))).toBe(false);
  });

  it("compares a scheduled run with the schedule's run before it", async () => {
    const schedule = await db
      .insertInto("scan_schedules")
      .values({ scanner_agent_id: agent.id, target_spec: "198.18.1.0/24", port_spec: "22,80", schedule_type: "interval", interval_minutes: 1440, next_run_at: new Date(Date.now() + DAY), created_by: "it" } as never)
      .returning("id")
      .executeTakeFirstOrThrow();
    const run = async (startedDaysAgo: number, hosts: Array<[string, number[]]>) => {
      const started = new Date(Date.now() - startedDaysAgo * DAY);
      const job = await db
        .insertInto("scan_jobs")
        .values({ scanner_agent_id: agent.id, target_spec: "198.18.1.0/24", port_spec: "22,80", status: "completed", started_at: started, finished_at: new Date(started.getTime() + 60_000) })
        .returning("id")
        .executeTakeFirstOrThrow();
      await db
        .insertInto("scan_requests")
        .values({ scanner_agent_id: agent.id, target_spec: "198.18.1.0/24", port_spec: "22,80", status: "completed", schedule_id: schedule.id, scan_job_id: job.id, requested_by: "schedule" } as never)
        .execute();
      for (const [ip, ports] of hosts) {
        const h = await db
          .insertInto("hosts")
          .values({ ip, scanner_agent_id: agent.id } as never)
          .onConflict((oc) => oc.columns(["ip", "scanner_agent_id"]).doUpdateSet({ last_seen_at: new Date() }))
          .returning("id")
          .executeTakeFirstOrThrow();
        for (const port of ports) {
          await db.insertInto("host_port_observations").values({ host_id: h.id, scan_job_id: job.id, port, protocol: "tcp", state: "open" } as never).execute();
        }
      }
      return job.id;
    };
    const first = await run(2, [["198.18.1.1", [22]], ["198.18.1.2", [22, 80]]]);
    const second = await run(1, [["198.18.1.1", [22, 80]], ["198.18.1.3", [22]]]);

    const none = await client.get(`/api/scan-jobs/${first}/compare-previous`);
    expect(none.body.previous).toBeNull();
    const res = await client.get(`/api/scan-jobs/${second}/compare-previous`);
    expect(res.body.previous.id).toBe(first);
    expect(res.body.newHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["198.18.1.3"]);
    expect(res.body.goneHosts.items.map((h: { ip: string }) => h.ip)).toEqual(["198.18.1.2"]);
    expect(res.body.opened.items).toMatchObject([{ ip: "198.18.1.1", port: "80/tcp" }]);
    expect(res.body.closed.total).toBe(0);
    // A scan nobody scheduled has no previous run.
    const adhoc = await db.insertInto("scan_jobs").values({ scanner_agent_id: agent.id, target_spec: "198.18.2.1", port_spec: "22", status: "completed" }).returning("id").executeTakeFirstOrThrow();
    expect((await client.get(`/api/scan-jobs/${adhoc.id}/compare-previous`)).status).toBe(400);
    expect((await restrictedClient.get(`/api/scan-jobs/${second}/compare-previous`)).status).toBe(404);
    const history = await client.get(`/api/scan-jobs/history?q=198.18.1.0`);
    expect(history.body.items.find((i: { id: string }) => i.id === second).schedule_id).toBe(schedule.id);
  });

  it("bundles a channel's host alerts into one message, and sends a lone one as itself", async () => {
    const created = await client.post("/api/webhooks").send({ name: `it-patch-bundle-${Date.now()}`, channelType: "webhook", url: hookUrl, events: ["host.new", "scanner.offline"], bundleMinutes: 2 });
    expect(created.status).toBe(201);
    expect(created.body.bundle_minutes).toBe(2);
    received = [];
    await dispatchWebhook("host.new", "New host discovered: 198.18.9.1", { ip: "198.18.9.1" });
    await dispatchWebhook("host.new", "New host discovered: 198.18.9.2", { ip: "198.18.9.2" });
    // Fleet-level events are never held back.
    await dispatchWebhook("scanner.offline", "Scanner x offline", {});
    await new Promise((r) => setTimeout(r, 400));
    expect(received.map((r) => r.event)).toEqual(["scanner.offline"]);

    // Not yet due, then due.
    expect(await flushBundles(new Date())).toBe(0);
    expect(await flushBundles(new Date(Date.now() + 3 * 60_000))).toBe(1);
    await new Promise((r) => setTimeout(r, 200));
    const bundle = received.find((r) => r.event === "alerts.bundle")!;
    expect(bundle.data.count).toBe(2);
    expect(bundle.text).toContain("2 alerts in the last 2 minutes");
    expect(bundle.text).toContain("198.18.9.2");

    received = [];
    await dispatchWebhook("host.new", "New host discovered: 198.18.9.3", { ip: "198.18.9.3" });
    await flushBundles(new Date(Date.now() + 3 * 60_000));
    await new Promise((r) => setTimeout(r, 200));
    expect(received.map((r) => r.event)).toEqual(["host.new"]);
    expect(await db.selectFrom("webhook_bundle_items").select("id").where("webhook_id", "=", created.body.id).execute()).toHaveLength(0);
  });

  it("builds the weekly report and sends it once, on Monday at the digest hour", async () => {
    const report = await computeWeeklyReport();
    expect(report.hosts.total).toBeGreaterThanOrEqual(3);
    expect(report.exposure.longUptime).toBeGreaterThanOrEqual(1);
    const preview = await client.get("/api/digest/weekly-report");
    expect(preview.body.text).toContain("PortTorch weekly report");
    expect((await restrictedClient.get("/api/digest/weekly-report")).status).toBe(403);

    const created = await client.post("/api/webhooks").send({ name: `it-patch-weekly-${Date.now()}`, channelType: "webhook", url: hookUrl, events: ["report.weekly"] });
    expect(created.status).toBe(201);
    const hour = (await client.get("/api/settings/app")).body.digestEmailHourUtc as number;
    await db.updateTable("weekly_report_state").set({ last_sent_week: null }).where("id", "=", 1).execute();
    const monday = new Date(Date.UTC(2026, 9, 19, hour, 5));
    const tuesday = new Date(Date.UTC(2026, 9, 20, hour, 5));
    received = [];
    expect(await weeklyTick(tuesday)).toBe(false);
    expect(await weeklyTick(monday)).toBe(true);
    expect(await weeklyTick(monday)).toBe(false);
    await new Promise((r) => setTimeout(r, 300));
    expect(received.filter((r) => r.event === "report.weekly")).toHaveLength(1);
  });
});
