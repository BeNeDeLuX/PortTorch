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
      index: null,
      sourcetype: null,
      verifyTls: true,
    });
  });

  it("sends nothing while no collector is configured", async () => {
    await addAudit("it.hec.unconfigured");
    const counts = await runHecForward();
    expect(counts).toEqual({ audit: 0, scanLog: 0 });
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
});
