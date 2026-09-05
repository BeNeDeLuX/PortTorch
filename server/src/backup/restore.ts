import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import zlib from "zlib";
import { pipeline } from "stream/promises";
import { logger } from "../logger";
import { config } from "../config";
import {
  BackupManifest,
  parseManifest,
  pgConnection,
  pgDumpToFile,
  run,
} from "./archive";

const REQUIRED_MEMBERS = ["manifest.txt", "db.sql.gz", "data.tar.gz"] as const;

export class RestoreError extends Error {}
/** The archive is fine, it just doesn't belong in this build. */
export class RestoreSchemaError extends RestoreError {}

async function runCapture(cmd: string, args: string[]): Promise<string> {
  const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (c) => {
    stdout += c.toString();
  });
  child.stderr.on("data", (c) => {
    stderr += c.toString();
  });
  await new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(stderr.trim() || `${cmd} exited ${code}`))));
  });
  return stdout;
}

/**
 * An uploaded archive is attacker-influenceable input. Two things stop a
 * tar entry named `../../etc/passwd` from landing there, and it is worth
 * being precise about which does the work, because it is not this
 * function:
 *
 *  1. Both extractions below name the members they want explicitly, so
 *     an archive's extra entries are never unpacked at all.
 *  2. busybox tar (what the runtime image ships) strips a leading `/` or
 *     `../` from member names itself and warns on stderr.
 *
 * Verified rather than assumed: an archive carrying
 * `./screenshots/../../escaped.txt` and `/abs-escaped.txt` extracted
 * neither outside the target directory. That same test is why this check
 * cannot be the protection - busybox reports the *sanitised* names, so a
 * hostile path never reaches it. It stays as defence in depth for a tar
 * implementation that does not sanitise.
 */
function assertSafeMembers(members: string[]): void {
  for (const member of members) {
    if (member.startsWith("/") || member.split("/").includes("..")) {
      throw new RestoreError(`archive contains an unsafe path (${member}) - refusing to extract it`);
    }
  }
}

function tarMembers(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

/** Newest migration this build ships, for comparison against the archive's. */
function localSchemaMigration(): string {
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, "migrations");
    if (fs.existsSync(candidate)) {
      const names = fs
        .readdirSync(candidate)
        .filter((f) => f.endsWith(".js"))
        .map((f) => f.replace(/\.js$/, ""))
        .sort();
      if (names.length > 0) return names[names.length - 1];
    }
    dir = path.join(dir, "..");
  }
  return "unknown";
}

async function psqlRestore(gzippedDump: string): Promise<void> {
  const { env, args } = pgConnection();
  const child = spawn("psql", [...args, "-v", "ON_ERROR_STOP=1", "--quiet", "-o", "/dev/null"], {
    env: {
      ...process.env,
      ...env,
      // The dump's DROP statements have to take exclusive locks on tables
      // this very process is still querying from its background tickers.
      // Those queries are milliseconds long, so a 30s ceiling never
      // trips in normal operation - but without one, a single unlucky
      // overlap would hang the restore indefinitely with no way to tell
      // that from a slow one.
      PGOPTIONS: "-c lock_timeout=30000",
    },
    stdio: ["pipe", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (c) => {
    stderr += c.toString();
  });
  const exited = new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(stderr.trim() || `psql exited ${code}`))));
  });
  await Promise.all([
    pipeline(fs.createReadStream(gzippedDump), zlib.createGunzip(), child.stdin),
    exited,
  ]);
}

/**
 * Replaces the screenshot directory's contents with the archive's.
 *
 * The staging directory is created *inside* the screenshot directory on
 * purpose: that directory is its own volume mount, so a sibling temp
 * directory under /data is a different filesystem and every move across
 * would be a full copy (EXDEV). Staged in-place, the swap is a series of
 * renames.
 */
async function restoreScreenshots(dataTar: string): Promise<{ restored: number; warning?: string }> {
  const dir = path.resolve(config.screenshotDir);
  fs.mkdirSync(dir, { recursive: true });

  const members = tarMembers(await runCapture("tar", ["tzf", dataTar]));
  assertSafeMembers(members);
  // Entries *under* ./screenshots/, not the bare directory entry itself -
  // tar records that even for an empty directory, and treating it as
  // "this archive has screenshots" made a backup taken with none look
  // like an extraction failure: the old files were kept instead of
  // cleared, with a warning saying so. Caught by restoring a genuinely
  // empty-screenshot backup, not by reading the code.
  const hasScreenshots = members.some((m) => m.startsWith("./screenshots/") && m !== "./screenshots/");

  const staging = fs.mkdtempSync(path.join(dir, ".porttorch-restore-"));
  try {
    let extractError: string | undefined;
    if (hasScreenshots) {
      try {
        await run("tar", ["xzf", dataTar, "-C", staging, "./screenshots"]);
      } catch (err) {
        // Deliberately not fatal, and deliberately not trusted either.
        // busybox tar can exit non-zero while having extracted the
        // requested member perfectly well - it does exactly that when an
        // archive also holds entries whose names it had to sanitise. So
        // the exit code is recorded and what actually landed on disk is
        // what decides below.
        extractError = err instanceof Error ? err.message : String(err);
      }
    }

    const extracted = path.join(staging, "screenshots");
    const staged = fs.existsSync(extracted) ? fs.readdirSync(extracted) : [];

    // The one case worth refusing to act on: the archive says it has
    // screenshots and none of them came out. Clearing the live directory
    // here would throw away the only copy left in exchange for nothing.
    if (hasScreenshots && staged.length === 0) {
      return {
        restored: 0,
        warning:
          `The database was restored, but the screenshots could not be unpacked, so the existing ones were left in ` +
          `place. ${extractError ?? "The archive's screenshot entries could not be read."}`,
      };
    }

    // Cleared even when the archive holds no screenshots at all: the
    // database rows referencing these files were just replaced, so
    // anything left behind is an orphan by definition.
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      if (full === staging) continue;
      fs.rmSync(full, { recursive: true, force: true });
    }

    let restored = 0;
    for (const entry of staged) {
      fs.renameSync(path.join(extracted, entry), path.join(dir, entry));
      restored++;
    }
    return {
      restored,
      warning: extractError
        ? `Restored ${restored} screenshot file(s), but tar reported a problem reading the archive: ${extractError}`
        : undefined,
    };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

export interface RestoreResult {
  manifest: BackupManifest;
  screenshotsRestored: number;
  /** Set when the database restore succeeded but the screenshots did not fully. */
  warning?: string;
}

/**
 * Applies an uploaded backup archive: database first, then screenshots.
 *
 * Deliberately does **not** restore the TLS certificate the archive also
 * carries. A certificate identifies *this* deployment - restoring one
 * taken from another instance would install a certificate issued for a
 * different hostname, breaking the very connection an admin would need to
 * put it right. scripts/restore.sh still restores it, which is the right
 * behaviour for the case that script exists for (rebuilding one host from
 * its own backup) and the wrong one here.
 */
export async function restoreFromArchive(archivePath: string): Promise<RestoreResult> {
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "porttorch-restore-"));
  try {
    const members = tarMembers(await runCapture("tar", ["tzf", archivePath]));
    assertSafeMembers(members);
    const normalised = new Set(members.map((m) => m.replace(/^\.\//, "").replace(/\/$/, "")));
    const missing = REQUIRED_MEMBERS.filter((m) => !normalised.has(m));
    if (missing.length > 0) {
      throw new RestoreError(
        `this is not a PortTorch backup archive - it is missing ${missing.join(", ")}`
      );
    }

    await run("tar", ["xzf", archivePath, "-C", staging, ...REQUIRED_MEMBERS]);
    const manifest = parseManifest(fs.readFileSync(path.join(staging, "manifest.txt"), "utf8"));

    // Restoring an *older* backup is normal and safe: the entrypoint runs
    // migrations on the restart that follows, bringing it up to date.
    // The other direction cannot work - the dump references tables and
    // columns this build's code knows nothing about - and unlike
    // scripts/restore.sh, which warns and leaves the call to an operator
    // with a shell, someone doing this from the dashboard would be left
    // with a broken instance and no way in. So this one refuses.
    const local = localSchemaMigration();
    const archived = manifest.schema_migration;
    if (archived && archived !== "unknown" && local !== "unknown" && archived > local) {
      throw new RestoreSchemaError(
        `This backup was taken on a newer schema (${archived}) than this webserver has (${local}). ` +
          `Update the webserver to at least that version first, then restore.`
      );
    }

    const dataTar = path.join(staging, "data.tar.gz");
    const screenshotFree = (() => {
      try {
        const stat = fs.statfsSync(path.resolve(config.screenshotDir));
        return Number(stat.bavail) * Number(stat.bsize);
      } catch {
        return Number.MAX_SAFE_INTEGER;
      }
    })();
    // Screenshots are PNG and barely compress, so the archive member's
    // own size is a fair proxy for what unpacking it needs - times three,
    // since the old set is still in place while the new one is staged
    // beside it.
    const needed = fs.statSync(dataTar).size * 3;
    if (screenshotFree < needed) {
      throw new RestoreError(
        `Not enough free space to unpack the screenshots: ${Math.round(screenshotFree / 1048576)} MB free, ` +
          `about ${Math.round(needed / 1048576)} MB needed.`
      );
    }

    // Taken before anything is dropped, so a dump that fails halfway
    // through leaves a recoverable database rather than a half-dropped
    // schema and no shell to fix it from. Database only - screenshots are
    // replaced after the database restore has already succeeded, so they
    // are never touched on this path.
    const rollback = path.join(staging, "rollback.sql.gz");
    await pgDumpToFile(rollback);

    try {
      await psqlRestore(path.join(staging, "db.sql.gz"));
    } catch (err) {
      logger.error({
        event: "backup.restore_failed",
        err: err instanceof Error ? err.message : String(err),
        msg: "database restore failed - rolling back to the pre-restore dump",
      });
      try {
        await psqlRestore(rollback);
        throw new RestoreError(
          `Restoring the database failed, and the previous contents were put back. ${
            err instanceof Error ? err.message : String(err)
          }`
        );
      } catch (rollbackErr) {
        if (rollbackErr instanceof RestoreError) throw rollbackErr;
        logger.error({
          event: "backup.rollback_failed",
          err: rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr),
        });
        throw new RestoreError(
          `Restoring the database failed AND rolling back failed. The database is in an inconsistent state - ` +
            `restore from a known-good archive with scripts/restore.sh on the host. ` +
            `${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    const screenshots = await restoreScreenshots(dataTar);
    return { manifest, screenshotsRestored: screenshots.restored, warning: screenshots.warning };
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}
