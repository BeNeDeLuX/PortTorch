import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { runSchedulerTick } from "../../src/scheduler";
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
// collide with genuine data when this suite runs against a copy of a
// real database. Its own /24 slice, distinct from the other suites that
// already use nearby ones (serviceAutoTags, adhocScans).
const IP = "240.7.6.5";
const IP_SCHEDULED = "240.7.6.6";

async function createScanJob(agent: TestAgent, targetSpec = IP): Promise<string> {
  const res = await request(getApp())
    .post("/api/ingest/scan-jobs")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ targetSpec, portSpec: "22" });
  expect(res.status).toBe(201);
  return res.body.id;
}

async function submitHost(
  agent: TestAgent,
  scanJobId: string,
  ip: string,
  ports: Array<{ port: number; protocol?: string; state?: string; serviceName?: string }>,
  tags?: string[]
) {
  const res = await request(getApp())
    .post("/api/ingest/hosts")
    .set("Authorization", `Bearer ${agent.apiKey}`)
    .send({ scanJobId, ...(tags ? { tags } : {}), hosts: [{ ip, ports }] });
  expect(res.status).toBe(204);
}

async function hostIdFor(agent: TestAgent, ip: string): Promise<string> {
  const row = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", ip)
    .where("scanner_agent_id", "=", agent.id)
    .executeTakeFirstOrThrow();
  return row.id;
}

async function tagsFor(hostId: string): Promise<string[]> {
  const rows = await db.selectFrom("host_tags").select(["tag"]).where("host_id", "=", hostId).orderBy("tag").execute();
  return rows.map((r) => r.tag);
}

// Tags requested on an Ad-hoc Scan or a Schedule (see lib/scanTags.ts) -
// applied to every host the scan actually touches, so "find exactly what
// this scan found" is a tag filter afterwards. The wire format is a
// top-level `tags` field on POST /api/ingest/hosts, echoed by the scanner
// from what GET /api/ingest/scan-requests/next handed it - this suite
// covers both ends of that round trip plus the ingest-side application.
describe("scan-requested tags", () => {
  let agent: TestAgent;
  let admin: TestUser;
  let client: SessionClient;
  const createdScanRequestIds: string[] = [];
  const createdScheduleIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-scan-tags-agent");
    admin = await createTestUser("admin");
    client = await loginAs(admin.username, admin.password);
  });

  afterAll(async () => {
    for (const id of createdScanRequestIds) {
      await db.deleteFrom("scan_requests").where("id", "=", id).execute();
    }
    for (const id of createdScheduleIds) {
      await db.deleteFrom("scan_schedules").where("id", "=", id).execute();
    }
    await db.deleteFrom("hosts").where("ip", "in", [IP, IP_SCHEDULED]).execute();
    await deleteTestUser(admin.id);
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  afterEach(async () => {
    await db.deleteFrom("scan_jobs").where("target_spec", "in", [IP, IP_SCHEDULED]).execute();
  });

  it("echoes a claimed request's tags back to the scanner", async () => {
    const createRes = await client.post("/api/adhoc-scans").send({
      scannerAgentId: agent.id,
      targetSpec: IP,
      portSpec: "22",
      tags: ["Q3-Audit", "external-range"],
    });
    expect(createRes.status).toBe(201);
    createdScanRequestIds.push(createRes.body.id);

    const claimRes = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${agent.apiKey}`);
    expect(claimRes.status).toBe(200);
    expect(claimRes.body.id).toBe(createRes.body.id);
    expect(claimRes.body.tags).toEqual(["Q3-Audit", "external-range"]);
  });

  it("applies requested tags to a host alongside its service-derived auto-tags", async () => {
    const jobId = await createScanJob(agent);
    await submitHost(
      agent,
      jobId,
      IP,
      [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }],
      ["Q3-Audit", "external-range"]
    );

    const hostId = await hostIdFor(agent, IP);
    // SSH-Server is service-derived (serviceTags.ts); the other two are
    // what this scan explicitly requested - both land in the same table,
    // by design (see ingest/routes.ts's ingestHostPayload).
    expect(await tagsFor(hostId)).toEqual(["Q3-Audit", "SSH-Server", "external-range"]);
  });

  it("records the two kinds of tag under different audit actors", async () => {
    const hostId = await hostIdFor(agent, IP);
    // recordAudit is deliberately not awaited on the ingest path (a slow
    // audit write must not hold up a scanner's submission), so the rows
    // can land a moment after the response. Wait for them rather than
    // racing them - this failed intermittently in the full suite.
    const find = async () => {
      const rows = await db
        .selectFrom("audit_log")
        .select(["actor", "details"])
        .where("event", "=", "host.tag_added")
        .where("actor", "in", ["auto-tag", "scan-tag"])
        .execute();
      const entry = (tag: string) =>
        rows.find((r) => (r.details as { tag?: string })?.tag === tag && (r.details as { host_id?: string })?.host_id === hostId);
      return { sshEntry: entry("SSH-Server"), auditEntry: entry("Q3-Audit") };
    };
    let found = await find();
    for (let i = 0; i < 20 && !(found.sshEntry && found.auditEntry); i++) {
      await new Promise((r) => setTimeout(r, 100));
      found = await find();
    }
    const { sshEntry, auditEntry } = found;
    expect(sshEntry?.actor).toBe("auto-tag");
    expect(auditEntry?.actor).toBe("scan-tag");
  });

  it("re-ingesting the same requested tags again does not error or duplicate them", async () => {
    const jobId = await createScanJob(agent);
    await submitHost(
      agent,
      jobId,
      IP,
      [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }],
      ["Q3-Audit", "external-range"]
    );

    const hostId = await hostIdFor(agent, IP);
    expect(await tagsFor(hostId)).toEqual(["Q3-Audit", "SSH-Server", "external-range"]);
  });

  it("adds nothing extra when a submission carries no tags at all", async () => {
    const jobId = await createScanJob(agent);
    // No tags argument - the one-shot CLI/menu/local-REST shape, and an
    // ad-hoc scan or schedule that never requested any.
    await submitHost(agent, jobId, IP, [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }]);

    const hostId = await hostIdFor(agent, IP);
    // Unchanged from before - nothing removed either, matching the
    // never-auto-removed reasoning the service tags already document.
    expect(await tagsFor(hostId)).toEqual(["Q3-Audit", "SSH-Server", "external-range"]);
  });

  it("copies a schedule's tags onto every scan_requests row it spawns", async () => {
    const scheduleRes = await client.post("/api/schedules").send({
      scheduleType: "interval",
      scannerAgentId: agent.id,
      targetSpec: IP_SCHEDULED,
      portSpec: "22",
      intervalMinutes: 60,
      tags: ["nightly-sweep"],
    });
    expect(scheduleRes.status).toBe(201);
    createdScheduleIds.push(scheduleRes.body.id);

    // Due immediately, same as scheduleSkip.integration.test.ts's own
    // fixture pattern.
    await db
      .updateTable("scan_schedules")
      .set({ next_run_at: new Date(Date.now() - 1000).toISOString() })
      .where("id", "=", scheduleRes.body.id)
      .execute();

    await runSchedulerTick();

    const spawned = await db
      .selectFrom("scan_requests")
      .select(["id", "tags"])
      .where("schedule_id", "=", scheduleRes.body.id)
      .executeTakeFirstOrThrow();
    createdScanRequestIds.push(spawned.id);
    expect(spawned.tags).toEqual(["nightly-sweep"]);

    // And the full round trip from there behaves exactly like an ad-hoc
    // request's own tags do.
    const claimRes = await request(getApp())
      .get("/api/ingest/scan-requests/next")
      .set("Authorization", `Bearer ${agent.apiKey}`);
    expect(claimRes.status).toBe(200);
    expect(claimRes.body.tags).toEqual(["nightly-sweep"]);

    // A port with no service-tag mapping at all (serviceTags.ts's RULES
    // table), so the only tag that can land here is the schedule's own -
    // port 22 would also auto-tag SSH-Server via its port-number
    // fallback even with no serviceName, which isn't what this assertion
    // is about.
    const jobId = await createScanJob(agent, IP_SCHEDULED);
    await submitHost(agent, jobId, IP_SCHEDULED, [{ port: 9999, protocol: "tcp", state: "open" }], claimRes.body.tags);

    const hostId = await hostIdFor(agent, IP_SCHEDULED);
    expect(await tagsFor(hostId)).toEqual(["nightly-sweep"]);

    await db.updateTable("scan_requests").set({ status: "completed" }).where("id", "=", spawned.id).execute();
  });
});
