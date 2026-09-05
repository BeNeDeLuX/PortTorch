import { db } from "../db";
import { logger } from "../logger";
import { config } from "../config";
import { VERSION } from "../version";

// Hourly, matching the scanner release sync beside it - a new webserver
// image appears when someone pushes to master, not minute to minute, and
// Docker Hub's unauthenticated rate limit is generous next to one call an
// hour.
const SYNC_INTERVAL_MS = 60 * 60_000;
const REQUEST_TIMEOUT_MS = 15_000;

// Only plain X.Y.Z tags. The same repository also carries ":latest" and a
// tag per commit SHA (see .github/workflows/webserver-docker.yml), and
// neither answers "is a newer release available" - "latest" always
// compares equal to itself, and a SHA has no order.
const VERSION_TAG = /^\d+\.\d+\.\d+$/;

// A third independent copy, like the two already documented in the root
// CLAUDE.md (Go scanner, TS frontend) - self-contained enough that a
// shared package isn't worth the coupling.
function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

interface DockerHubTag {
  name: string;
  last_updated: string | null;
}

export function startWebserverReleaseSync(): void {
  const tick = () =>
    syncWebserverRelease().catch((err) =>
      logger.error({
        event: "webserver_release_sync.tick_failed",
        err: err instanceof Error ? err.message : String(err),
      })
    );
  tick();
  setInterval(tick, SYNC_INTERVAL_MS);
}

/**
 * Reads the newest X.Y.Z tag from Docker Hub into the singleton cache.
 *
 * A failure is *recorded*, not just logged: without that, a registry that
 * has been unreachable for a week looks identical to one confirming the
 * running version is current, which is the more dangerous of the two to
 * get wrong. The cached version is left in place so the dashboard can
 * still show the last known answer alongside how stale it is.
 */
export async function syncWebserverRelease(): Promise<void> {
  const url = `https://hub.docker.com/v2/repositories/${config.webserverImageRepo}/tags?page_size=100&ordering=last_updated`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "porttorch-webserver", Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`Docker Hub returned ${res.status}`);
    }
    const body = (await res.json()) as { results?: DockerHubTag[] };
    const versions = (body.results ?? []).filter((t) => VERSION_TAG.test(t.name));
    if (versions.length === 0) {
      throw new Error("no version-shaped tags found");
    }
    // Newest by version, not by publish date: a rebuild of an older
    // version would otherwise present itself as the newest release.
    const latest = versions.reduce((best, t) => (compareSemver(t.name, best.name) > 0 ? t : best));

    await db
      .updateTable("webserver_release_cache")
      .set({
        latest_version: latest.name,
        image_tag: `${config.webserverImageRepo}:${latest.name}`,
        published_at: latest.last_updated ? new Date(latest.last_updated) : null,
        synced_at: new Date(),
        last_error: null,
      })
      .where("id", "=", 1)
      .execute();

    logger.info({
      event: "webserver_release_sync.completed",
      latest_version: latest.name,
      running_version: VERSION,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db
      .updateTable("webserver_release_cache")
      .set({ synced_at: new Date(), last_error: message })
      .where("id", "=", 1)
      .execute()
      .catch(() => {});
    throw err;
  }
}

export interface WebserverReleaseStatus {
  runningVersion: string;
  latestVersion: string | null;
  imageTag: string | null;
  publishedAt: Date | null;
  syncedAt: Date | null;
  lastError: string | null;
  // Null when there is nothing to compare against yet - deliberately
  // distinct from false, so the UI can say "not checked" rather than
  // implying the running version was confirmed current.
  updateAvailable: boolean | null;
}

export async function getWebserverReleaseStatus(): Promise<WebserverReleaseStatus> {
  const row = await db
    .selectFrom("webserver_release_cache")
    .select(["latest_version", "image_tag", "published_at", "synced_at", "last_error"])
    .where("id", "=", 1)
    .executeTakeFirst();

  const runningVersion = VERSION;
  const latestVersion = row?.latest_version ?? null;
  return {
    runningVersion,
    latestVersion,
    imageTag: row?.image_tag ?? null,
    publishedAt: row?.published_at ?? null,
    syncedAt: row?.synced_at ?? null,
    lastError: row?.last_error ?? null,
    // A running version *newer* than the registry's is normal on a
    // machine building from source, and is not an update - hence a
    // strict "newer than running" rather than "different from".
    updateAvailable: latestVersion === null ? null : compareSemver(latestVersion, runningVersion) > 0,
  };
}
