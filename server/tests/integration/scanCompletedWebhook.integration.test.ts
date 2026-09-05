import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "http";
import { AddressInfo } from "net";
import request from "supertest";
import { db } from "../../src/db";
import { closeDb, createTestAgent, deleteTestAgent, getApp, type TestAgent } from "./helpers";

const IP = "240.34.0.1";

// Eighteen webhook events existed and none of them fired when a scan
// finished - so anything wanting to react to "scan done, fetch the
// results" had to poll.
describe("scan.completed webhook", () => {
  let agent: TestAgent;
  let receiver: http.Server;
  let webhookId: string;
  const received: Array<{ event: string; data: Record<string, unknown> }> = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-scan-completed");

    receiver = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        try {
          received.push(JSON.parse(body));
        } catch {
          // A malformed body is a test bug, not something to hide.
        }
        res.writeHead(200);
        res.end();
      });
    });
    await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
    const port = (receiver.address() as AddressInfo).port;

    const hook = await db
      .insertInto("webhooks")
      .values({
        name: "it-scan-completed",
        channel_type: "webhook",
        url: `http://127.0.0.1:${port}/hook`,
        events: ["scan.completed"],
        enabled: true,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    webhookId = hook.id;
  });

  afterAll(async () => {
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await db.deleteFrom("hosts").where("ip", "=", IP).execute();
    await db.deleteFrom("scan_jobs").where("target_spec", "=", IP).execute();
    await deleteTestAgent(agent.id);
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
    await closeDb();
  });

  async function runScan(finalStatus: "completed" | "cancelled"): Promise<void> {
    const job = await request(getApp())
      .post("/api/ingest/scan-jobs")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ targetSpec: IP, portSpec: "22,443" });
    await request(getApp())
      .post("/api/ingest/hosts")
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({
        scanJobId: job.body.id,
        hosts: [{ ip: IP, ports: [{ port: 22, protocol: "tcp", state: "open", serviceName: "ssh" }] }],
      });
    await request(getApp())
      .patch(`/api/ingest/scan-jobs/${job.body.id}`)
      .set("Authorization", `Bearer ${agent.apiKey}`)
      .send({ status: finalStatus });
    // Dispatch is fire-and-forget so scanner ingest is never slowed by a
    // slow target - give the delivery a moment to land.
    await new Promise((r) => setTimeout(r, 800));
  }

  it("fires with the counts read from the database, not from the scanner's own tally", async () => {
    await runScan("completed");
    const event = received.find((e) => e.event === "scan.completed");
    expect(event).toBeDefined();
    expect(event!.data.targetSpec).toBe(IP);
    expect(event!.data.portSpec).toBe("22,443");
    expect(event!.data.hostsScanned).toBe(1);
    expect(event!.data.openPortsFound).toBe(1);
    expect(event!.data.scannerAgentName).toBe(agent.name);
    expect(typeof event!.data.durationMs).toBe("number");
  });

  it("does not fire for a cancelled scan", async () => {
    received.length = 0;
    await runScan("cancelled");
    // A cancellation is a person deciding to stop. An event that fired
    // for it would mean "a scan ended", which is not what anyone wants to
    // trigger a results-fetch on.
    expect(received.find((e) => e.event === "scan.completed")).toBeUndefined();
  });
});
