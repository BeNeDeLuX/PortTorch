import http from "http";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runHecForward } from "../../src/hec/forwarder";
import { setHecSettings } from "../../src/settings/appSettings";
import { closeDb, createTestAgent, deleteTestAgent, type TestAgent } from "./helpers";

// A real collector, not a mock of our own client: what is under test is
// the wire format an actual HEC endpoint receives - concatenated JSON
// objects, "Splunk <token>" auth - which a stubbed fetch would never
// exercise.
interface Received {
  auth: string | undefined;
  events: Array<Record<string, any>>;
}

describe("HEC log forwarding", () => {
  let server: http.Server;
  let baseUrl: string;
  let received: Received[] = [];
  let failNext = false;
  let agent: TestAgent;
  const auditEvents: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-hec-agent");
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        if (failNext) {
          res.writeHead(503).end("collector down");
          return;
        }
        const body = Buffer.concat(chunks).toString("utf8");
        // HEC's format: one JSON object after another, never an array.
        const events = body
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l));
        received.push({ auth: req.headers.authorization, events });
        res.writeHead(200, { "content-type": "application/json" }).end('{"text":"Success","code":0}');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await db.deleteFrom("audit_log").where("event", "in", auditEvents.length ? auditEvents : ["__none__"]).execute();
    await db.deleteFrom("scan_jobs").where("scanner_agent_id", "=", agent.id).execute();
    await setHecSettings({
      url: null,
      token: null,
      auditEnabled: false,
      scanLogEnabled: false,
      observationsEnabled: false,
      findingsEnabled: false,
      index: null,
      sourcetype: null,
      verifyTls: true,
    });
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  beforeEach(async () => {
    received = [];
    failNext = false;
    // Start each case from "everything so far is already forwarded", so
    // pre-existing audit rows from other suites don't drown the assertions.
    const latest = await db.selectFrom("audit_log").select(["id"]).orderBy("id", "desc").limit(1).executeTakeFirst();
    await db
      .updateTable("hec_state")
      .set({
        audit_cursor: latest ? latest.id : null,
        scan_log_cursor_at: new Date().toISOString(),
        scan_log_cursor_job_id: null,
        observation_cursor: null,
        finding_cursor_at: null,
        finding_cursor_id: null,
        last_error: null,
      })
      .where("id", "=", 1)
      .execute();
  });

  async function configure(patch: Partial<Parameters<typeof setHecSettings>[0]> = {}) {
    await setHecSettings({
      url: baseUrl,
      token: "test-token",
      auditEnabled: true,
      scanLogEnabled: true,
      observationsEnabled: false,
      findingsEnabled: false,
      index: null,
      sourcetype: null,
      verifyTls: true,
      ...patch,
    });
  }

  async function addAudit(event: string): Promise<void> {
    auditEvents.push(event);
    await db
      .insertInto("audit_log")
      .values({ event, actor: "it-hec", source_ip: "10.9.9.9", details: { note: event } })
      .execute();
  }

  async function addScanLog(lines: number): Promise<string> {
    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: "240.70.0.0/24", port_spec: "80", status: "completed" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    await db
      .insertInto("scan_job_full_log")
      .values({
        scan_job_id: job.id,
        logs: JSON.stringify(
          Array.from({ length: lines }, (_, i) => ({
            time: new Date(Date.now() + i).toISOString(),
            stage: "masscan",
            message: `line ${i}`,
          }))
        ),
      })
      .execute();
    return job.id;
  }

  afterEach(async () => {
    await setHecSettings({
      url: null,
      token: null,
      auditEnabled: false,
      scanLogEnabled: false,
      observationsEnabled: false,
      findingsEnabled: false,
      index: null,
      sourcetype: null,
      verifyTls: true,
    });
  });

  it("sends nothing while no collector is configured", async () => {
    await addAudit("it.hec.unconfigured");
    const counts = await runHecForward();
    expect(counts).toEqual({ audit: 0, scanLog: 0, observations: 0, findings: 0 });
    expect(received).toHaveLength(0);
  });

  it("forwards audit rows with Splunk's auth scheme and event envelope", async () => {
    await configure({ scanLogEnabled: false });
    await addAudit("it.hec.audit-one");

    const counts = await runHecForward();
    expect(counts.audit).toBe(1);
    expect(received).toHaveLength(1);
    expect(received[0].auth).toBe("Splunk test-token");

    const event = received[0].events[0];
    expect(event.source).toBe("porttorch:audit");
    expect(typeof event.time).toBe("number");
    expect(event.event.event).toBe("it.hec.audit-one");
    expect(event.event.actor).toBe("it-hec");
    expect(event.event.details).toEqual({ note: "it.hec.audit-one" });
  });

  it("does not resend what it already forwarded", async () => {
    await configure({ scanLogEnabled: false });
    await addAudit("it.hec.once");
    expect((await runHecForward()).audit).toBe(1);

    received = [];
    expect((await runHecForward()).audit).toBe(0);
    expect(received).toHaveLength(0);
  });

  it("leaves the cursor alone when the collector rejects the batch, then catches up", async () => {
    // The whole reason this is a cursor and not fire-and-forget: an
    // outage must produce a delay, never a silent gap.
    await configure({ scanLogEnabled: false });
    await addAudit("it.hec.during-outage");

    failNext = true;
    expect((await runHecForward()).audit).toBe(0);
    expect(received).toHaveLength(0);

    const state = await db.selectFrom("hec_state").select(["last_error"]).where("id", "=", 1).executeTakeFirstOrThrow();
    expect(state.last_error).toContain("503");

    failNext = false;
    expect((await runHecForward()).audit).toBe(1);
    expect(received[0].events[0].event.event).toBe("it.hec.during-outage");
  });

  it("forwards one event per scan log line, batched across requests", async () => {
    await configure({ auditEnabled: false });
    await addScanLog(450);

    const counts = await runHecForward();
    expect(counts.scanLog).toBe(450);

    // MAX_EVENTS_PER_POST is 200, so a 450-line log cannot arrive in one
    // request - batching by event is what bounds the request size.
    expect(received.length).toBeGreaterThan(1);
    const all = received.flatMap((r) => r.events);
    expect(all).toHaveLength(450);
    expect(all[0].source).toBe("porttorch:scan");
    expect(all[0].event.target_spec).toBe("240.70.0.0/24");
    expect(all[0].event.scanner_agent_name).toBe(agent.name);
    expect(all[0].event.message).toBe("line 0");
    // The half no test covered before: the cursor has to actually
    // advance. A timestamp cursor round-tripped through a JS Date loses
    // sub-millisecond precision, so "created_at > cursor" stays true for
    // the very row it was taken from - and the whole log is re-sent on
    // every tick, forever.
    received.length = 0;
    expect((await runHecForward()).scanLog).toBe(0);
    expect(received).toHaveLength(0);
  });

  it("honours the two toggles independently", async () => {
    await configure({ auditEnabled: true, scanLogEnabled: false });
    await addAudit("it.hec.toggle");
    await addScanLog(3);

    const counts = await runHecForward();
    expect(counts.audit).toBe(1);
    expect(counts.scanLog).toBe(0);
    expect(received.flatMap((r) => r.events).every((e) => e.source === "porttorch:audit")).toBe(true);
  });

  it("applies the configured index and sourcetype", async () => {
    await configure({ scanLogEnabled: false, index: "netsec", sourcetype: "porttorch:custom" });
    await addAudit("it.hec.indexed");

    await runHecForward();
    expect(received[0].events[0].index).toBe("netsec");
    expect(received[0].events[0].sourcetype).toBe("porttorch:custom");
  });

  // The gap these two close: the audit trail says who pressed what and
  // the scan log says what the scanner was doing, while the findings
  // themselves - which port opened, what nuclei matched - reached a SIEM
  // only as fire-and-forget webhook posts, with no cursor and no
  // backfill.
  it("forwards port observations as one event each, with the address resolved", async () => {
    await configure({ auditEnabled: false, scanLogEnabled: false, observationsEnabled: true });

    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: "240.71.0.0/24", port_spec: "22", status: "completed" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    const host = await db
      .insertInto("hosts")
      .values({ ip: "240.71.0.9", scanner_agent_id: agent.id, hostname: "it-hec-host.internal" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    await db
      .insertInto("host_port_observations")
      .values([
        { host_id: host.id, scan_job_id: job.id, port: 22, protocol: "tcp", state: "open", service_name: "ssh" },
        { host_id: host.id, scan_job_id: job.id, port: 80, protocol: "tcp", state: "closed", service_name: "http" },
      ])
      .execute();

    const counts = await runHecForward();
    expect(counts.observations).toBe(2);

    const events = received.flatMap((r) => r.events);
    expect(events).toHaveLength(2);
    // The address, not just an internal uuid - a SIEM keys on the former.
    expect(events[0].event.ip).toBe("240.71.0.9");
    expect(events[0].event.hostname).toBe("it-hec-host.internal");
    expect(events[0].source).toBe("porttorch:observation");
    // A closed port is carried too: a port that stopped answering is a
    // change worth correlating, not an absence to drop.
    expect(events.map((e) => e.event.state).sort()).toEqual(["closed", "open"]);

    // Second pass sends nothing - the cursor advanced.
    received.length = 0;
    expect((await runHecForward()).observations).toBe(0);
    expect(received).toHaveLength(0);

    await db.deleteFrom("hosts").where("id", "=", host.id).execute();
    await db.deleteFrom("scan_jobs").where("id", "=", job.id).execute();
  });

  it("forwards nuclei findings and resumes from its own cursor", async () => {
    await configure({ auditEnabled: false, scanLogEnabled: false, findingsEnabled: true });

    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: "240.72.0.0/24", port_spec: "443", status: "completed" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    const host = await db
      .insertInto("hosts")
      .values({ ip: "240.72.0.9", scanner_agent_id: agent.id })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    await db
      .insertInto("nuclei_findings")
      .values({
        host_id: host.id,
        scan_job_id: job.id,
        port: 443,
        template_id: "it-hec-template",
        name: "An integration test finding",
        severity: "high",
        matched_at: "https://240.72.0.9/",
        tags: ["it", "test"],
      })
      .execute();

    const counts = await runHecForward();
    expect(counts.findings).toBe(1);
    const event = received.flatMap((r) => r.events)[0];
    expect(event.source).toBe("porttorch:finding");
    expect(event.event.template_id).toBe("it-hec-template");
    // nuclei's own severity word, not remapped onto a SIEM's scale.
    expect(event.event.severity).toBe("high");
    expect(event.event.ip).toBe("240.72.0.9");
    expect(event.event.tags).toEqual(["it", "test"]);

    received.length = 0;
    expect((await runHecForward()).findings).toBe(0);

    await db.deleteFrom("hosts").where("id", "=", host.id).execute();
    await db.deleteFrom("scan_jobs").where("id", "=", job.id).execute();
  });
});
