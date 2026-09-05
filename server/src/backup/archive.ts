import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import zlib from "zlib";
import { pipeline } from "stream/promises";
import { sql } from "kysely";
import { db } from "../db";
import { config } from "../config";
import { VERSION } from "../version";

// The archive this produces is byte-for-byte the same *shape* as
// scripts/backup.sh's: a gzipped tar of manifest.txt + db.sql.gz +
// data.tar.gz. That compatibility is the point, not an accident - a
// backup taken from the dashboard has to be restorable with
// scripts/restore.sh (the disaster-recovery path, which still works when
// the webserver won't start at all), and an archive taken by the nightly
// systemd timer has to be uploadable here. Two formats would mean the one
// you have is never the one the situation calls for.
//
// What differs is *how* it's produced. The script runs pg_dump inside the
// postgres container and reads the volumes through `docker run
// --volumes-from`, because it has a Docker socket. This process has
// neither - but it does have a database connection and both /data volumes
// mounted, which is all the archive actually needs.

export interface BackupManifest {
  created_at?: string;
  host?: string;
  checkout_version?: string;
  webserver_image?: string;
  git_commit?: string;
  schema_migration?: string;
  created_by?: string;
  source?: string;
}

/**
 * Connection parameters for pg_dump/psql, taken from the same
 * DATABASE_URL the app itself connects with, so a dump can't be taken
 * against a different database than the one being served.
 *
 * Split into flags plus PGPASSWORD rather than passed as a single URI
 * argument: command-line arguments are visible in the process list, and a
 * connection URI carries the password in it.
 */
export function pgConnection(): { env: Record<string, string>; args: string[] } {
  const url = new URL(config.databaseUrl);
  return {
    env: { PGPASSWORD: decodeURIComponent(url.password) },
    args: [
      "-h",
      url.hostname,
      "-p",
      url.port || "5432",
      "-U",
      decodeURIComponent(url.username),
      "-d",
      url.pathname.replace(/^\//, ""),
    ],
  };
}

export async function run(cmd: string, args: string[], env?: Record<string, string>): Promise<void> {
  const child = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  await new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `${cmd} exited with code ${code}`));
    });
  });
}

/** pg_dump straight into a gzip file, no shell and no intermediate plain-text dump on disk. */
export async function pgDumpToFile(dest: string): Promise<void> {
  const { env, args } = pgConnection();
  const child = spawn("pg_dump", [...args, "--clean", "--if-exists", "--no-owner"], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const exited = new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `pg_dump exited with code ${code}`));
    });
  });
  await Promise.all([
    pipeline(child.stdout, zlib.createGzip({ level: 9 }), fs.createWriteStream(dest, { mode: 0o600 })),
    exited,
  ]);
}

export function formatManifest(manifest: BackupManifest): string {
  return (
    Object.entries(manifest)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${k}=${v}`)
      .join("\n") + "\n"
  );
}

export function parseManifest(text: string): BackupManifest {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

/** The schema the dump is being taken at, read from node-pg-migrate's own bookkeeping table. */
export async function currentSchemaMigration(): Promise<string> {
  try {
    const result = await sql<{ name: string }>`SELECT name FROM pgmigrations ORDER BY id DESC LIMIT 1`.execute(db);
    return result.rows[0]?.name ?? "unknown";
  } catch {
    return "unknown";
  }
}

function directoryBytes(dir: string): number {
  let total = 0;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return 0;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    try {
      if (entry.isDirectory()) total += directoryBytes(full);
      else if (entry.isFile()) total += fs.statSync(full).size;
    } catch {
      // Raced with a delete, or unreadable - not worth failing an
      // estimate over.
    }
  }
  return total;
}

export interface BackupEstimate {
  databaseBytes: number;
  screenshotBytes: number;
  certBytes: number;
  /** Rough uncompressed total - what the disk check is measured against. */
  totalBytes: number;
  freeBytes: number;
  /** False when staging an archive would leave the disk uncomfortably full. */
  enoughSpace: boolean;
}

export async function estimateBackup(): Promise<BackupEstimate> {
  let databaseBytes = 0;
  try {
    const result = await sql<{ bytes: string }>`SELECT pg_database_size(current_database())::text AS bytes`.execute(db);
    databaseBytes = Number(result.rows[0]?.bytes ?? 0);
  } catch {
    databaseBytes = 0;
  }
  const screenshotBytes = directoryBytes(path.resolve(config.screenshotDir));
  const certBytes = directoryBytes(path.resolve(config.certDir));
  const totalBytes = databaseBytes + screenshotBytes + certBytes;

  let freeBytes = 0;
  try {
    const stat = fs.statfsSync(os.tmpdir());
    freeBytes = Number(stat.bavail) * Number(stat.bsize);
  } catch {
    freeBytes = Number.MAX_SAFE_INTEGER;
  }

  return {
    databaseBytes,
    screenshotBytes,
    certBytes,
    totalBytes,
    freeBytes,
    enoughSpace: freeBytes >= requiredFreeBytes(totalBytes),
  };
}

// Staging holds db.sql.gz + data.tar.gz and then the finished archive
// containing both, so roughly twice the compressed size at peak. The
// estimate above is *uncompressed*, so doubling it is already generous
// for screenshots (PNG, barely compressible) and very generous for the
// database (SQL text, compresses hard). The flat 128 MB on top is so a
// small fleet on a nearly-full disk still fails the check rather than
// filling the last of it.
export function requiredFreeBytes(totalBytes: number): number {
  return totalBytes * 2 + 128 * 1024 * 1024;
}

export interface CreatedArchive {
  /** Absolute path of the finished .tar.gz. */
  path: string;
  filename: string;
  bytes: number;
  manifest: BackupManifest;
  /** Removes the whole staging directory, archive included. */
  cleanup: () => void;
}

/**
 * Builds a complete backup archive in a temporary directory. The caller
 * owns it from here and must call cleanup() once the bytes are delivered.
 */
export async function createBackupArchive(createdBy: string): Promise<CreatedArchive> {
  const estimate = await estimateBackup();
  if (!estimate.enoughSpace) {
    throw new BackupSpaceError(
      `Not enough free disk space to stage a backup: ${Math.round(estimate.freeBytes / 1048576)} MB free, ` +
        `about ${Math.round(requiredFreeBytes(estimate.totalBytes) / 1048576)} MB needed.`
    );
  }

  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "porttorch-backup-"));
  const cleanup = () => {
    try {
      fs.rmSync(staging, { recursive: true, force: true });
    } catch {
      // Best effort - a leftover temp directory is not worth failing on.
    }
  };

  try {
    await pgDumpToFile(path.join(staging, "db.sql.gz"));
    if (fs.statSync(path.join(staging, "db.sql.gz")).size === 0) {
      throw new Error("database dump came back empty - refusing to write a useless backup");
    }

    // The two /data directories are separately configurable and needn't
    // share a parent, and busybox tar (what the runtime image ships)
    // takes only one -C. A directory of symlinks tarred with -h
    // dereferences to the real content while giving the archive the
    // ./screenshots + ./certs layout scripts/restore.sh expects,
    // wherever the originals actually live.
    const linkDir = path.join(staging, "data");
    fs.mkdirSync(linkDir);
    fs.symlinkSync(path.resolve(config.screenshotDir), path.join(linkDir, "screenshots"));
    fs.symlinkSync(path.resolve(config.certDir), path.join(linkDir, "certs"));
    await run("tar", ["czhf", path.join(staging, "data.tar.gz"), "-C", linkDir, "."]);
    fs.rmSync(linkDir, { recursive: true, force: true });

    const manifest: BackupManifest = {
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      host: os.hostname(),
      checkout_version: VERSION,
      // Neither is knowable from inside the container - it has no Docker
      // socket to inspect itself with and no git checkout. Kept as
      // explicit "unknown" rather than omitted, so the field set matches
      // what scripts/backup.sh writes and restore.sh reads.
      webserver_image: "unknown",
      git_commit: "unknown",
      schema_migration: await currentSchemaMigration(),
      created_by: createdBy,
      source: "dashboard",
    };
    fs.writeFileSync(path.join(staging, "manifest.txt"), formatManifest(manifest));

    const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "Z").replace("T", "-");
    const filename = `porttorch-${timestamp}.tar.gz`;
    const archivePath = path.join(staging, filename);
    await run("tar", ["czf", archivePath, "-C", staging, "manifest.txt", "db.sql.gz", "data.tar.gz"]);
    // Contains the TLS private key and every password hash in the
    // database.
    fs.chmodSync(archivePath, 0o600);

    return { path: archivePath, filename, bytes: fs.statSync(archivePath).size, manifest, cleanup };
  } catch (err) {
    cleanup();
    throw err;
  }
}

export class BackupSpaceError extends Error {}
