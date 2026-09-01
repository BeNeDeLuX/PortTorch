import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sql } from "kysely";
import { db } from "../../src/db";
import {
  closeDb,
  createTestAgent,
  createTestUser,
  deleteTestAgent,
  deleteTestUser,
  loginAs,
  type TestAgent,
  type TestUser,
} from "./helpers";

// Class E (240.0.0.0/4) - reserved, so nothing here collides with real
// data when the suite runs against a copy of a production database.
const HOST_A = "240.60.0.1";
const HOST_B = "240.60.0.2";

interface GalleryItem {
  id: string;
  host_id: string;
  host_ip: string;
  port: number;
  page_title: string | null;
  kind: "web" | "rdp";
  captured_at: string;
}

// The gallery is a fleet-wide overview, not a history: one tile per host
// and port, newest capture only.
describe("fleet-wide screenshot gallery", () => {
  let agent: TestAgent;
  let viewer: TestUser;
  let hostA: string;
  let hostB: string;
  let jobId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-gallery-agent");
    viewer = await createTestUser("user");

    const job = await db
      .insertInto("scan_jobs")
      .values({ scanner_agent_id: agent.id, target_spec: HOST_A, port_spec: "80", status: "completed" })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    jobId = job.id;

    for (const ip of [HOST_A, HOST_B]) {
      const host = await db
        .insertInto("hosts")
        .values({ ip, scanner_agent_id: agent.id })
        .returning(["id"])
        .executeTakeFirstOrThrow();
      if (ip === HOST_A) hostA = host.id;
      else hostB = host.id;
    }

    const shot = (hostId: string, port: number, title: string, minutesAgo: number) => ({
      host_id: hostId,
      scan_job_id: jobId,
      port,
      url: `http://x:${port}/`,
      image_path: `/nonexistent/${hostId}-${port}-${minutesAgo}.png`,
      page_title: title,
      captured_at: new Date(Date.now() - minutesAgo * 60_000).toISOString(),
    });

    await db
      .insertInto("screenshots")
      .values([
        // Same host and port captured twice - only the newer one belongs
        // in the gallery. This is the "no history" rule.
        shot(hostA, 80, "old title", 120),
        shot(hostA, 80, "current title", 5),
        // A second port on the same host is a genuinely different
        // interface and must not be collapsed away.
        shot(hostA, 8080, "admin panel", 10),
        shot(hostB, 443, "other host", 60),
      ])
      .execute();

    await db
      .insertInto("rdp_screenshots")
      .values({
        host_id: hostB,
        scan_job_id: jobId,
        port: 3389,
        image_path: "/nonexistent/rdp.png",
        captured_at: new Date(Date.now() - 30 * 60_000).toISOString(),
      })
      .execute();
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip = ${HOST_A}::inet OR ip = ${HOST_B}::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("id", "=", jobId).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(viewer.id);
    await closeDb();
  });

  async function gallery(): Promise<GalleryItem[]> {
    const client = await loginAs(viewer.username, viewer.password);
    const res = await client.get("/api/screenshots");
    expect(res.status).toBe(200);
    return res.body.filter((s: GalleryItem) => [HOST_A, HOST_B].includes(s.host_ip));
  }

  it("shows only the newest capture per host and port", async () => {
    const items = await gallery();
    const forPort80 = items.filter((s) => s.host_ip === HOST_A && s.port === 80);
    expect(forPort80).toHaveLength(1);
    expect(forPort80[0].page_title).toBe("current title");
  });

  it("keeps a second port on the same host as its own tile", async () => {
    const items = await gallery();
    const forHostA = items.filter((s) => s.host_ip === HOST_A).map((s) => s.port);
    expect(forHostA.sort()).toEqual([80, 8080]);
  });

  it("includes RDP captures alongside web ones", async () => {
    const items = await gallery();
    const rdp = items.filter((s) => s.kind === "rdp");
    expect(rdp).toHaveLength(1);
    expect(rdp[0].port).toBe(3389);
    expect(rdp[0].host_id).toBe(hostB);
  });

  it("returns newest first", async () => {
    const items = await gallery();
    const times = items.map((s) => new Date(s.captured_at).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));
  });

  it("links each tile to a host that actually exists", async () => {
    // The whole interaction is "click a tile, land on that host", so a
    // host_id that doesn't resolve would break the only thing this page
    // is for.
    const items = await gallery();
    const client = await loginAs(viewer.username, viewer.password);
    for (const item of items) {
      const res = await client.get(`/api/hosts/${item.host_id}`);
      expect(res.status).toBe(200);
    }
  });

  it("requires authentication", async () => {
    const { default: request } = await import("supertest");
    const { getApp } = await import("./helpers");
    const res = await request(getApp()).get("/api/screenshots");
    expect(res.status).toBe(401);
  });
});
