import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { db } from "../../src/db";
import { parseScanSlotsHeader } from "../../src/ingest/apiKeyAuth";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  getApp,
  loginAs,
  type TestAgent,
  type TestUser,
} from "./helpers";

// maxConcurrentScans made a scanner's capacity a real number, but the
// webserver only ever knew it when an admin had set it as a dashboard
// override - so "is this scanner saturated or idle?" was unanswerable
// from here. It now rides along on every request.
describe("scanner scan-slot reporting", () => {
  let agent: TestAgent;
  let admin: TestUser;

  beforeAll(async () => {
    agent = await createTestAgent("it-slots-agent");
    admin = await createTestUser("admin");
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await deleteTestUser(admin.id);
    await closeDb();
  });

  async function ping(header?: string): Promise<void> {
    const req = request(getApp()).get("/api/ingest/excludes").set("Authorization", `Bearer ${agent.apiKey}`);
    if (header !== undefined) req.set("X-Scanner-Scan-Slots", header);
    const res = await req;
    expect(res.status).toBe(200);
  }

  async function slots() {
    return db
      .selectFrom("scanner_agents")
      .select(["scan_slots_running", "scan_slots_max"])
      .where("id", "=", agent.id)
      .executeTakeFirstOrThrow();
  }

  it("records what a serve-mode scanner reports", async () => {
    await ping("2/3");
    expect(await slots()).toEqual({ scan_slots_running: 2, scan_slots_max: 3 });
  });

  it("does not erase a known capacity when a request arrives without the header", async () => {
    // A one-shot "scan"/"menu" process on the same host, or an older
    // build: neither is evidence that the capacity changed, so the last
    // reported value stands.
    await ping();
    expect(await slots()).toEqual({ scan_slots_running: 2, scan_slots_max: 3 });
  });

  it("ignores a malformed value rather than storing it", async () => {
    for (const bad of ["", "3", "a/b", "1/0", "-1/2", "4/2"]) {
      await ping(bad);
      expect(await slots()).toEqual({ scan_slots_running: 2, scan_slots_max: 3 });
    }
  });

  it("surfaces the pair on the agents endpoint", async () => {
    await ping("0/4");
    const client = await loginAs(admin.username, admin.password);
    const res = await client.get("/api/agents");
    expect(res.status).toBe(200);
    const row = res.body.find((a: { id: string }) => a.id === agent.id);
    expect(row.scan_slots_running).toBe(0);
    expect(row.scan_slots_max).toBe(4);
  });
});

describe("parseScanSlotsHeader", () => {
  it("accepts a well-formed pair", () => {
    expect(parseScanSlotsHeader("0/1")).toEqual({ running: 0, max: 1 });
    expect(parseScanSlotsHeader("3/8")).toEqual({ running: 3, max: 8 });
  });

  it("returns null for everything that isn't one", () => {
    // Absent is the "unknown" case the whole design rests on.
    expect(parseScanSlotsHeader(undefined)).toBeNull();
    expect(parseScanSlotsHeader("2")).toBeNull();
    expect(parseScanSlotsHeader("2/3/4")).toBeNull();
    expect(parseScanSlotsHeader("x/3")).toBeNull();
    expect(parseScanSlotsHeader("2/0")).toBeNull();
    expect(parseScanSlotsHeader("-1/3")).toBeNull();
    // Only reachable as a transient while a lowered limit is applied -
    // not worth recording as a permanent-looking "5/2".
    expect(parseScanSlotsHeader("5/2")).toBeNull();
  });
});
