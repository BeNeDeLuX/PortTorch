import fs from "fs";
import os from "os";
import path from "path";
import sharp from "sharp";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sql } from "kysely";
import { config } from "../../src/config";
import { db } from "../../src/db";
import { deleteScreenshotFiles, purgeOrphanedScreenshotFiles } from "../../src/screenshots/files";
import { thumbPathFor } from "../../src/screenshots/thumbs";
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
  changed: boolean;
  previous: { id: string; captured_at: string; page_title: string | null; http_status: number | null } | null;
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
  });

  // The response is a page now; the search narrows it to this file's two
  // hosts, which also exercises the search itself.
  async function page(query = "", pageSize = 200): Promise<{ items: GalleryItem[]; total: number; excluded: number; counts: Record<string, number>; tags: Array<{ tag: string; count: number }> }> {
    const client = await loginAs(viewer.username, viewer.password);
    const res = await client.get(`/api/screenshots?pageSize=${pageSize}&q=240.60.0${query}`);
    expect(res.status).toBe(200);
    return res.body;
  }
  async function gallery(): Promise<GalleryItem[]> {
    return (await page()).items.filter((s: GalleryItem) => [HOST_A, HOST_B].includes(s.host_ip));
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

  it("carries the previous capture and flags a changed page title", async () => {
    // 10.0.0.11:80 went from "old title" to "current title" - the signal
    // this exists for (a login page becoming an open admin panel).
    const items = await gallery();
    const changed = items.find((s) => s.host_ip === HOST_A && s.port === 80)!;
    expect(changed.changed).toBe(true);
    expect(changed.previous).not.toBeNull();
    expect(changed.previous!.page_title).toBe("old title");
  });

  it("does not flag a first-ever capture as changed", async () => {
    // Nothing to differ from - flagging it would make every new host
    // noisy, which is how a badge stops being read.
    const items = await gallery();
    const first = items.find((s) => s.host_ip === HOST_A && s.port === 8080)!;
    expect(first.previous).toBeNull();
    expect(first.changed).toBe(false);
  });

  it("does not flag a repeat capture whose title and status are the same", async () => {
    // Two captures of an unchanged page. An image comparison would call
    // this a change on almost every scan; the stored metadata does not.
    const unchanged = await db
      .insertInto("screenshots")
      .values({
        host_id: hostB,
        scan_job_id: jobId,
        port: 443,
        url: "http://x:443/",
        image_path: "/nonexistent/b-443-new.png",
        page_title: "other host",
        captured_at: new Date().toISOString(),
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();

    const items = await gallery();
    const entry = items.find((s) => s.host_ip === HOST_B && s.port === 443)!;
    expect(entry.id).toBe(String(unchanged.id));
    expect(entry.previous).not.toBeNull();
    expect(entry.changed).toBe(false);
  });

  it("requires authentication", async () => {
    const { default: request } = await import("supertest");
    const { getApp } = await import("./helpers");
    const res = await request(getApp()).get("/api/screenshots");
    expect(res.status).toBe(401);
  });

  it("pages, and hides tiles by keyword - including what the scan learned about the host", async () => {
    const first = await page("", 2);
    expect(first.items).toHaveLength(2);
    expect(first.total).toBe(4);

    // Nothing on host B's page says "Cisco"; its manufacturer does.
    await db.updateTable("hosts").set({ mac_vendor: "Cisco Systems" }).where("id", "=", hostB).execute();
    const r = await page("&exclude=cisco,admin%20panel");
    expect(r.items.map((i) => `${i.host_ip}:${i.port}`)).toEqual([`${HOST_A}:80`]);
    expect(r.excluded).toBe(3);
    expect(r.counts).toMatchObject({ all: 1, rdp: 0 });
  });

  it("filters by tag either way, and lists the tags it saw", async () => {
    await db.insertInto("host_tags").values({ host_id: hostA, tag: "known" }).execute();
    const excluded = await page("&excludeTags=known");
    expect(excluded.items.every((i) => i.host_ip === HOST_B)).toBe(true);
    const only = await page("&tags=known");
    expect(only.items.every((i) => i.host_ip === HOST_A)).toBe(true);
    expect(only.tags).toContainEqual({ tag: "known", count: 2 });
  });
});

// Gallery tiles show a small preview, made once from the original and kept.
describe("screenshot previews", () => {
  let agent: TestAgent;
  let viewer: TestUser;
  let jobId: string;
  let hostId: string;
  const originalDir = config.screenshotDir;

  beforeAll(async () => {
    config.screenshotDir = fs.mkdtempSync(path.join(os.tmpdir(), "porttorch-thumbs-"));
    agent = await createTestAgent("it-thumb-agent");
    viewer = await createTestUser("user");
    jobId = (await db.insertInto("scan_jobs").values({ scanner_agent_id: agent.id, target_spec: "240.60.1.1", port_spec: "80", status: "completed" }).returning("id").executeTakeFirstOrThrow()).id;
    hostId = (await db.insertInto("hosts").values({ ip: "240.60.1.1", scanner_agent_id: agent.id }).returning("id").executeTakeFirstOrThrow()).id;
  });

  afterAll(async () => {
    await sql`DELETE FROM hosts WHERE ip = '240.60.1.1'::inet`.execute(db);
    await db.deleteFrom("scan_jobs").where("id", "=", jobId).execute();
    await deleteTestAgent(agent.id);
    await deleteTestUser(viewer.id);
    fs.rmSync(config.screenshotDir, { recursive: true, force: true });
    config.screenshotDir = originalDir;
    await closeDb();
  });

  it("serves a small WebP, keeps it, and removes it with its original", async () => {
    const original = path.join(config.screenshotDir, "capture-1.png");
    await sharp({ create: { width: 1920, height: 1080, channels: 3, background: "#2a4" } }).png().toFile(original);
    const row = await db
      .insertInto("screenshots")
      .values({ host_id: hostId, scan_job_id: jobId, port: 80, url: "http://x/", image_path: original })
      .returning("id")
      .executeTakeFirstOrThrow();

    const client = await loginAs(viewer.username, viewer.password);
    const res = await client.get(`/api/screenshots/${row.id}/thumb`).buffer(true).parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on("data", (c: Buffer) => chunks.push(c));
      r.on("end", () => cb(null, Buffer.concat(chunks)));
    });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("image/webp");
    const meta = await sharp(res.body as Buffer).metadata();
    expect(meta).toMatchObject({ format: "webp", width: 480 });
    expect((res.body as Buffer).length).toBeLessThan(fs.statSync(original).size);

    const thumb = thumbPathFor(original);
    expect(fs.existsSync(thumb)).toBe(true);
    // Unauthenticated callers get nothing, previews included.
    expect((await request(getApp()).get(`/api/screenshots/${row.id}/thumb`)).status).toBe(401);

    deleteScreenshotFiles([original]);
    expect(fs.existsSync(original)).toBe(false);
    expect(fs.existsSync(thumb)).toBe(false);
  });

  it("serves the original when it cannot make a preview", async () => {
    const broken = path.join(config.screenshotDir, "broken.png");
    fs.writeFileSync(broken, "not an image");
    const row = await db
      .insertInto("screenshots")
      .values({ host_id: hostId, scan_job_id: jobId, port: 81, url: "http://x/", image_path: broken })
      .returning("id")
      .executeTakeFirstOrThrow();
    const client = await loginAs(viewer.username, viewer.password);
    const res = await client.get(`/api/screenshots/${row.id}/thumb`);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("image/png");
  });

  it("collects previews whose original is gone, but not fresh ones", async () => {
    const thumbs = path.join(config.screenshotDir, "thumbs");
    fs.mkdirSync(thumbs, { recursive: true });
    const stale = path.join(thumbs, "gone.png.webp");
    const fresh = path.join(thumbs, "also-gone.png.webp");
    fs.writeFileSync(stale, "x");
    fs.writeFileSync(fresh, "x");
    const old = new Date(Date.now() - 2 * 60 * 60_000);
    fs.utimesSync(stale, old, old);
    await purgeOrphanedScreenshotFiles();
    expect(fs.existsSync(stale)).toBe(false);
    // Inside the grace period - it may be being written right now.
    expect(fs.existsSync(fresh)).toBe(true);
  });
});
