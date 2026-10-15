import fs from "fs";
import path from "path";
import { sql } from "kysely";
import { config } from "../config";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings } from "../settings/appSettings";
import { dispatchWebhook } from "../webhooks/dispatch";

// The webserver's own disk. Scanners report theirs with every metrics
// sample; this host held the database, every screenshot and every backup
// and said nothing, so a full disk was first noticed when Postgres stopped.
//
// What is measured is the filesystem holding the screenshot directory.
// With the shipped docker-compose.yml that is a named volume under
// /var/lib/docker, the same filesystem the database volume lives on, so
// it stands for both. A deployment that puts them on different disks gets
// the screenshot disk here; the database's size is reported beside it
// either way, from Postgres itself.

export interface StorageNow {
  measuredAt: Date;
  path: string;
  diskFreeBytes: number | null;
  diskTotalBytes: number | null;
  dbBytes: number;
}

// A directory that does not exist yet (no screenshot captured so far) is
// measured at its nearest existing parent - the filesystem it will be
// created on - the same rule the scanner uses for its submit queue.
export function diskUsage(start: string): { free: number; total: number } | null {
  for (let dir = path.resolve(start); ; dir = path.dirname(dir)) {
    try {
      const st = fs.statfsSync(dir);
      // bavail, not bfree: what a non-root writer can still use.
      return { free: Number(st.bavail) * Number(st.bsize), total: Number(st.blocks) * Number(st.bsize) };
    } catch {
      if (dir === path.dirname(dir)) return null;
    }
  }
}

export async function measureStorage(now = new Date()): Promise<StorageNow> {
  const disk = diskUsage(config.screenshotDir);
  const { rows } = await sql<{ size: string }>`SELECT pg_database_size(current_database()) AS size`.execute(db);
  return {
    measuredAt: now,
    path: config.screenshotDir,
    diskFreeBytes: disk?.free ?? null,
    diskTotalBytes: disk?.total ?? null,
    dbBytes: Number(rows[0]?.size ?? 0),
  };
}

// One row per day, overwritten through the day so it ends up holding the
// day's last measurement - growth is a per-day question.
export async function recordStorageSample(now = new Date()): Promise<StorageNow> {
  const m = await measureStorage(now);
  const day = now.toISOString().slice(0, 10);
  await db
    .insertInto("webserver_storage_samples")
    .values({ day, measured_at: now, db_bytes: m.dbBytes, disk_free_bytes: m.diskFreeBytes, disk_total_bytes: m.diskTotalBytes })
    .onConflict((oc) =>
      oc.column("day").doUpdateSet({
        measured_at: now,
        db_bytes: m.dbBytes,
        disk_free_bytes: m.diskFreeBytes,
        disk_total_bytes: m.diskTotalBytes,
      })
    )
    .execute();
  // A year of daily rows is plenty for a trend.
  await db.deleteFrom("webserver_storage_samples").where("day", "<", new Date(now.getTime() - 400 * 86_400_000).toISOString().slice(0, 10)).execute();
  return m;
}

// Fleet Health's view: now, the daily history, and - when free space has
// been shrinking - how long until it runs out at the recent pace. The pace
// is the average daily loss over the last 14 days of samples, and only a
// loss counts: a disk that is not filling has no "full by" date.
export async function storageStatus(now = new Date()) {
  const current = await measureStorage(now);
  const history = await db
    .selectFrom("webserver_storage_samples")
    .selectAll()
    .where("day", ">=", new Date(now.getTime() - 90 * 86_400_000).toISOString().slice(0, 10))
    .orderBy("day")
    .execute();
  const points = history.map((h) => ({
    day: new Date(h.day).toISOString().slice(0, 10),
    dbBytes: Number(h.db_bytes),
    diskFreeBytes: h.disk_free_bytes === null ? null : Number(h.disk_free_bytes),
  }));
  const recent = points.filter((p) => p.diskFreeBytes !== null && Date.parse(p.day) >= now.getTime() - 15 * 86_400_000);
  let freeLossPerDay: number | null = null;
  if (recent.length >= 2) {
    const first = recent[0];
    const last = recent[recent.length - 1];
    const days = (Date.parse(last.day) - Date.parse(first.day)) / 86_400_000;
    if (days > 0) freeLossPerDay = (first.diskFreeBytes! - last.diskFreeBytes!) / days;
  }
  const dbRecent = points.filter((p) => Date.parse(p.day) >= now.getTime() - 15 * 86_400_000);
  const dbGrowthPerDay =
    dbRecent.length >= 2
      ? (dbRecent[dbRecent.length - 1].dbBytes - dbRecent[0].dbBytes) /
        Math.max(1, (Date.parse(dbRecent[dbRecent.length - 1].day) - Date.parse(dbRecent[0].day)) / 86_400_000)
      : null;
  const { diskLowPercent } = await getAppSettings();
  const freePercent =
    current.diskFreeBytes !== null && current.diskTotalBytes ? (100 * current.diskFreeBytes) / current.diskTotalBytes : null;
  return {
    ...current,
    diskFreePercent: freePercent,
    diskLowPercent,
    diskLow: freePercent !== null && freePercent < diskLowPercent,
    freeLossPerDay,
    dbGrowthPerDay,
    daysUntilFull: freeLossPerDay && freeLossPerDay > 0 && current.diskFreeBytes !== null ? current.diskFreeBytes / freeLossPerDay : null,
    history: points,
  };
}

// webserver.disk_low - same come-and-go shape and the same admin
// threshold as scanner.disk_low, re-armed five points above the line.
export async function checkWebserverDisk(now = new Date()): Promise<boolean> {
  const m = await recordStorageSample(now);
  if (m.diskFreeBytes === null || !m.diskTotalBytes) return false;
  const pct = (100 * m.diskFreeBytes) / m.diskTotalBytes;
  const { diskLowPercent } = await getAppSettings();
  const state = await db.selectFrom("app_settings").select("webserver_disk_alert_sent_at").where("id", "=", 1).executeTakeFirstOrThrow();
  if (pct < diskLowPercent && !state.webserver_disk_alert_sent_at) {
    await dispatchWebhook(
      "webserver.disk_low",
      `The PortTorch webserver has ${pct.toFixed(1)}% disk space left (${(m.diskFreeBytes / 1024 ** 3).toFixed(1)} GB). The database, screenshots and backups live there - once it is full, Postgres stops accepting writes.`,
      { free_bytes: m.diskFreeBytes, total_bytes: m.diskTotalBytes, free_percent: Math.round(pct * 10) / 10, database_bytes: m.dbBytes, path: m.path }
    );
    await db.updateTable("app_settings").set({ webserver_disk_alert_sent_at: now }).where("id", "=", 1).execute();
    return true;
  }
  if (pct >= diskLowPercent + 5 && state.webserver_disk_alert_sent_at) {
    await db.updateTable("app_settings").set({ webserver_disk_alert_sent_at: null }).where("id", "=", 1).execute();
  }
  return false;
}

export function startWebserverStorage(): void {
  const run = () =>
    checkWebserverDisk().catch((err) => logger.error({ event: "webserver_storage.check_failed", err: err instanceof Error ? err.message : String(err) }));
  setTimeout(run, 60_000);
  setInterval(run, 15 * 60_000);
}
