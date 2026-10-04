import { execFileSync } from "child_process";
import fs from "fs";
import http from "http";
import type { AddressInfo } from "net";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { backupTick } from "../../src/backup/schedule";
import { listObjects } from "../../src/backup/s3";
import { db } from "../../src/db";
import { closeDb, createTestUser, deleteTestUser, loginAs, type SessionClient, type TestUser } from "./helpers";

// A real archive needs pg_dump and tar, as in the runtime image; and the
// targets need a writable directory and an S3-compatible store. All three
// are provided by the run that exercises this file (see server/CLAUDE.md);
// without them it is skipped rather than failed.
const hasPgDump = (() => {
  try {
    execFileSync("pg_dump", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();
const BACKUP_DIR = process.env.BACKUP_TEST_DIR;
const S3_ENDPOINT = process.env.S3_TEST_ENDPOINT;
const S3 = { accessKey: "porttorchtest", secretKey: "porttorch-test-secret-123", bucket: "porttorch-backups" };

const archives = (dir: string) => fs.readdirSync(dir).filter((n) => /^porttorch-.*\.tar\.gz$/.test(n)).sort();
// Archive names have one-second resolution; two runs inside one second
// would write the same name.
const nextSecond = () => new Promise((r) => setTimeout(r, 1100));

describe.skipIf(!hasPgDump || !BACKUP_DIR)("scheduled backups", () => {
  let admin: TestUser;
  let operator: TestUser;
  let adminClient: SessionClient;
  let op: SessionClient;
  let server: http.Server;
  let received: Array<{ event: string; data: Record<string, unknown> }> = [];
  let webhookId: string;

  const directorySettings = (over: Record<string, unknown> = {}) => ({
    enabled: true,
    hourUtc: 2,
    keep: 2,
    target: "directory",
    directory: BACKUP_DIR,
    s3: { endpoint: null, region: "us-east-1", bucket: null, prefix: "porttorch/", accessKey: null, pathStyle: true },
    ...over,
  });

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
          name: `it-backup-${Date.now()}`,
          channel_type: "webhook",
          url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`,
          events: ["backup.failed"],
          enabled: true,
        })
        .returning("id")
        .executeTakeFirstOrThrow()
    ).id;
    admin = await createTestUser("admin");
    operator = await createTestUser("operator");
    adminClient = await loginAs(admin.username, admin.password);
    op = await loginAs(operator.username, operator.password);
    for (const n of fs.readdirSync(BACKUP_DIR!)) fs.rmSync(path.join(BACKUP_DIR!, n), { force: true, recursive: true });
  });

  afterAll(async () => {
    await db
      .updateTable("app_settings")
      .set({ backup_schedule_enabled: false, backup_s3_secret_key: null, backup_last_date: null, backup_last_status: null })
      .where("id", "=", 1)
      .execute();
    await db.deleteFrom("webhooks").where("id", "=", webhookId).execute();
    await deleteTestUser(admin.id);
    await deleteTestUser(operator.id);
    server.close();
    await closeDb();
  });

  it("is admin-only, and refuses to switch on a schedule that cannot run", async () => {
    expect((await op.get("/api/settings/backup/schedule")).status).toBe(403);
    const refused = await adminClient.put("/api/settings/backup/schedule").send(directorySettings({ directory: null }));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toContain("directory");
    expect((await adminClient.put("/api/settings/backup/schedule").send(directorySettings({ directory: "relative/path" }))).status).toBe(400);
    expect((await adminClient.put("/api/settings/backup/schedule").send(directorySettings())).status).toBe(200);
  });

  it("writes the archive to the directory and keeps only the newest", async () => {
    // Someone else's file in the same share must survive pruning.
    fs.writeFileSync(path.join(BACKUP_DIR!, "notes.txt"), "keep me");
    for (let i = 0; i < 3; i++) {
      const run = await adminClient.post("/api/settings/backup/schedule/run-now");
      expect(run.body.ok).toBe(true);
      expect(run.body.bytes).toBeGreaterThan(0);
      if (i < 2) await nextSecond();
    }
    const kept = archives(BACKUP_DIR!);
    expect(kept).toHaveLength(2);
    expect(fs.existsSync(path.join(BACKUP_DIR!, "notes.txt"))).toBe(true);
    // It holds every password hash and the TLS key.
    expect(fs.statSync(path.join(BACKUP_DIR!, kept[1])).mode & 0o777).toBe(0o600);
    // A real archive: the three members restore.sh expects.
    const members = execFileSync("tar", ["tzf", path.join(BACKUP_DIR!, kept[1])]).toString().split("\n").filter(Boolean).sort();
    expect(members).toEqual(["data.tar.gz", "db.sql.gz", "manifest.txt"]);

    const status = (await adminClient.get("/api/settings/backup/schedule")).body;
    expect(status.last).toMatchObject({ status: "succeeded", error: null, location: path.join(BACKUP_DIR!, kept[1]) });
  });

  it("records and alerts a failure, keeping the last success visible", async () => {
    await adminClient.put("/api/settings/backup/schedule").send(directorySettings({ directory: "/does/not/exist" }));
    received = [];
    const run = await adminClient.post("/api/settings/backup/schedule/run-now");
    expect(run.body.ok).toBe(false);
    expect(run.body.error).toContain("does not exist");
    for (let i = 0; i < 40 && received.length === 0; i++) await new Promise((r) => setTimeout(r, 50));
    expect(received.map((r) => r.event)).toContain("backup.failed");
    const status = (await adminClient.get("/api/settings/backup/schedule")).body;
    expect(status.last.status).toBe("failed");
    expect(status.last.successAt).not.toBeNull();
  });

  it("runs once per day, in its hour", async () => {
    await adminClient.put("/api/settings/backup/schedule").send(directorySettings());
    await db.updateTable("app_settings").set({ backup_last_date: null }).where("id", "=", 1).execute();
    const before = archives(BACKUP_DIR!).length;
    await nextSecond();
    expect(await backupTick(new Date("2030-01-01T05:00:00Z"))).toBe(false); // not the hour
    expect(await backupTick(new Date("2030-01-01T02:10:00Z"))).toBe(true);
    expect(await backupTick(new Date("2030-01-01T02:40:00Z"))).toBe(false); // already ran today
    expect(archives(BACKUP_DIR!).length).toBe(Math.min(before + 1, 2));
  });

  it.skipIf(!S3_ENDPOINT)("uploads to S3, lists and prunes there, and keeps the secret back", async () => {
    const s3 = { endpoint: S3_ENDPOINT, region: "us-east-1", bucket: S3.bucket, prefix: "porttorch/", accessKey: S3.accessKey, pathStyle: true };
    const saved = await adminClient
      .put("/api/settings/backup/schedule")
      .send({ ...directorySettings(), keep: 1, target: "s3", directory: null, s3: { ...s3, secretKey: S3.secretKey } });
    expect(saved.status).toBe(200);
    expect(saved.body.s3).not.toHaveProperty("secretKey");
    expect(saved.body.s3.secretKeySet).toBe(true);

    const first = await adminClient.post("/api/settings/backup/schedule/run-now");
    expect(first.body).toMatchObject({ ok: true });
    expect(first.body.location).toMatch(/^s3:\/\/porttorch-backups\/porttorch\/porttorch-.*\.tar\.gz$/);
    await nextSecond();
    const second = await adminClient.post("/api/settings/backup/schedule/run-now");
    expect(second.body).toMatchObject({ ok: true, pruned: 1 });

    const cfg = { endpoint: S3_ENDPOINT!, region: "us-east-1", bucket: S3.bucket, accessKey: S3.accessKey, secretKey: S3.secretKey, pathStyle: true };
    const keys = await listObjects(cfg, "porttorch/");
    expect(keys).toEqual([second.body.location.replace("s3://porttorch-backups/", "")]);

    // A wrong secret is refused by the store's own signature check.
    await adminClient
      .put("/api/settings/backup/schedule")
      .send({ ...directorySettings(), target: "s3", directory: null, s3: { ...s3, secretKey: "wrong-secret" } });
    const refused = await adminClient.post("/api/settings/backup/schedule/run-now");
    expect(refused.body.ok).toBe(false);
    expect(refused.body.error).toMatch(/upload failed: 403/);
  });
});
