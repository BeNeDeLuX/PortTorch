import crypto from "crypto";
import fs from "fs";
import path from "path";
import sharp from "sharp";
import { config } from "../config";
import { logger } from "../logger";

// Small previews for the screenshot gallery.
//
// The gallery used to show every tile with the original capture - a
// 1920x1080 PNG, often several hundred kilobytes - in a tile about 300
// pixels wide. With 800 captures that is hundreds of megabytes of image
// data for the browser to fetch and decode while scrolling. A 480-pixel
// WebP is a few tens of kilobytes.
//
// Made on first request and kept, rather than at ingest: that covers every
// capture taken before this existed with no backfill job, and costs
// nothing for a capture nobody ever looks at. The original is untouched
// and still what a click opens.
//
// Named after the original's file rather than the row id, so whatever
// deletes an original can find its preview without a lookup - see
// deleteScreenshotFiles - and a preview whose original is gone is
// recognisable as an orphan on its own.

export const THUMB_WIDTH = 480;

export function thumbDir(): string {
  return path.join(path.resolve(config.screenshotDir), "thumbs");
}

export function thumbPathFor(imagePath: string): string {
  return path.join(thumbDir(), `${path.basename(imagePath)}.webp`);
}

/** Returns the preview's path, creating it if it does not exist yet. */
export async function ensureThumb(imagePath: string): Promise<string> {
  const thumb = thumbPathFor(imagePath);
  if (fs.existsSync(thumb)) return thumb;
  fs.mkdirSync(thumbDir(), { recursive: true });
  // A unique temporary name and a rename, so two requests for the same new
  // tile never serve each other's half-written file.
  const tmp = `${thumb}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    await sharp(imagePath).resize({ width: THUMB_WIDTH, withoutEnlargement: true }).webp({ quality: 70 }).toFile(tmp);
    fs.renameSync(tmp, thumb);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  return thumb;
}

// Previews whose original no longer exists. The originals' own orphan pass
// (files.ts) only looks at the top level of the screenshot directory, so
// this subdirectory needs its own - and the same grace period, so a
// preview being written right now is never taken for one.
export function purgeOrphanedThumbs(graceMs: number): number {
  let entries: string[];
  try {
    entries = fs.readdirSync(thumbDir());
  } catch {
    return 0;
  }
  const root = path.resolve(config.screenshotDir);
  const cutoff = Date.now() - graceMs;
  let deleted = 0;
  for (const entry of entries) {
    const full = path.join(thumbDir(), entry);
    try {
      const stat = fs.statSync(full);
      if (!stat.isFile() || stat.mtimeMs > cutoff) continue;
      // "<original>.webp" or a leftover "<original>.webp.<hex>.tmp".
      const original = entry.replace(/\.webp(\.[0-9a-f]+\.tmp)?$/, "");
      if (!entry.endsWith(".tmp") && fs.existsSync(path.join(root, original))) continue;
      fs.unlinkSync(full);
      deleted++;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        logger.warn({ event: "screenshot.thumb_cleanup_failed", path: full, err: err instanceof Error ? err.message : String(err) });
      }
    }
  }
  return deleted;
}
