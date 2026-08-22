import fs from "fs";
import path from "path";
import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";

// Deleting the image files behind screenshots/rdp_screenshots rows.
//
// Nothing in this codebase ever unlinked one. Every capture writes a
// fresh `<uuid>.png` (see ingest/routes.ts), so a host scanned hourly
// accumulates a file per HTTP/RDP port per scan indefinitely - and worse,
// deleting a host cascades its DB rows away while leaving the files
// behind with nothing referencing them at all. The database shrank, the
// disk never did, and the orphans were unfindable without reconciling
// the directory against image_path by hand.

// Only ever unlink inside the configured screenshot directory. Same
// resolve-and-prefix check screenshots/routes.ts already applies before
// serving a file - image_path comes from our own ingest handler, but a
// delete is destructive enough to re-verify rather than trust.
function isInsideScreenshotDir(filePath: string): boolean {
  const root = path.resolve(config.screenshotDir);
  const resolved = path.resolve(filePath);
  return resolved === root || resolved.startsWith(root + path.sep);
}

export function deleteScreenshotFiles(paths: Array<string | null | undefined>): number {
  let deleted = 0;
  for (const p of paths) {
    if (!p || !isInsideScreenshotDir(p)) continue;
    try {
      fs.unlinkSync(path.resolve(p));
      deleted++;
    } catch (err) {
      // A missing file is the expected case on a re-run or after a manual
      // cleanup, not a problem - anything else is worth knowing about but
      // must never fail the delete that triggered it.
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        logger.warn({ event: "screenshot.unlink_failed", path: p, err: err instanceof Error ? err.message : String(err) });
      }
    }
  }
  return deleted;
}

// The image paths belonging to these hosts. Must be called *before* the
// host row is deleted: the cascade takes the screenshot rows with it, and
// with them the only record of which files to remove.
export async function screenshotPathsForHosts(hostIds: string[]): Promise<string[]> {
  if (hostIds.length === 0) return [];
  const [http, rdp] = await Promise.all([
    db.selectFrom("screenshots").select(["image_path"]).where("host_id", "in", hostIds).execute(),
    db.selectFrom("rdp_screenshots").select(["image_path"]).where("host_id", "in", hostIds).execute(),
  ]);
  return [...http, ...rdp].map((r) => r.image_path);
}

// Age-based purge for hosts that are still very much alive: without it
// only host deletion would ever reclaim anything, so a long-lived host
// scanned on a schedule grows forever. Uses the same
// app_settings.host_retention_days window as the host sweep itself
// rather than a second knob - one answer to "how long do we keep
// history", as the audit_log purge already does.
export async function purgeOldScreenshots(threshold: Date): Promise<number> {
  const [http, rdp] = await Promise.all([
    db.deleteFrom("screenshots").where("captured_at", "<", threshold).returning(["image_path"]).execute(),
    db.deleteFrom("rdp_screenshots").where("captured_at", "<", threshold).returning(["image_path"]).execute(),
  ]);
  const rows = [...http, ...rdp];
  if (rows.length === 0) return 0;

  deleteScreenshotFiles(rows.map((r) => r.image_path));
  logger.info({ event: "retention.screenshots_purged", purged_count: rows.length, threshold: threshold.toISOString() });
  return rows.length;
}

// Files on disk that no row points at. This is what actually reclaims
// everything leaked before any of the above existed - without it those
// stay forever, since nothing knows they were ever screenshots.
//
// The grace period is load-bearing, not caution: ingest writes the file
// first and inserts the row immediately after, so a capture landing
// mid-sweep would otherwise look exactly like an orphan and be deleted
// out from under the insert. An hour is far longer than that window and
// costs nothing, since orphans are permanent until collected anyway.
const ORPHAN_GRACE_MS = 60 * 60_000;

export async function purgeOrphanedScreenshotFiles(): Promise<number> {
  const root = path.resolve(config.screenshotDir);
  let entries: string[];
  try {
    entries = fs.readdirSync(root);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      logger.warn({ event: "screenshot.orphan_scan_failed", err: err instanceof Error ? err.message : String(err) });
    }
    return 0;
  }
  if (entries.length === 0) return 0;

  // One query for the whole set rather than one per file - a directory
  // with tens of thousands of leaked captures is exactly the case this
  // exists for.
  const [http, rdp] = await Promise.all([
    db.selectFrom("screenshots").select(["image_path"]).execute(),
    db.selectFrom("rdp_screenshots").select(["image_path"]).execute(),
  ]);
  const referenced = new Set([...http, ...rdp].map((r) => path.resolve(r.image_path)));

  const cutoff = Date.now() - ORPHAN_GRACE_MS;
  const orphans: string[] = [];
  for (const entry of entries) {
    const full = path.join(root, entry);
    if (referenced.has(full)) continue;
    try {
      const stat = fs.statSync(full);
      if (!stat.isFile() || stat.mtimeMs > cutoff) continue;
      orphans.push(full);
    } catch {
      // Vanished between readdir and stat - nothing to do.
    }
  }

  if (orphans.length === 0) return 0;
  const deleted = deleteScreenshotFiles(orphans);
  logger.info({ event: "retention.orphaned_screenshots_purged", purged_count: deleted, scanned: entries.length });
  return deleted;
}
