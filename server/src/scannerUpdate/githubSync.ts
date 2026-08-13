import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";

// GitHub's unauthenticated REST API rate limit is 60 req/hour/IP - a
// single releases-list fetch per hour stays comfortably under that, same
// bulk-fetch-and-cache shape as cve/kevSync.ts (no per-release detail
// calls needed, GET /releases already returns each release's tag/html_url
// in one response).
const SYNC_INTERVAL_MS = 60 * 60_000;

const TAG_PREFIX = "scanner-v";

interface GitHubRelease {
  tag_name: string;
  html_url: string;
  draft: boolean;
  prerelease: boolean;
}

// Plain X.Y.Z compare - matches the scanner's own version.go convention
// (no pre-release/build-metadata suffixes in a scanner-vX.Y.Z tag), same
// "pragmatic, not spec-complete" tradeoff as cve/cpe.ts's cpe22to23.
function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

export function startGithubSync(): void {
  tick().catch((err) => logger.error({ event: "scanner_release_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "scanner_release_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, SYNC_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const res = await fetch(`https://api.github.com/repos/${config.githubRepoSlug}/releases`, {
    headers: {
      // GitHub's API rejects requests with no User-Agent at all.
      "User-Agent": "porttorch-webserver",
      Accept: "application/vnd.github+json",
    },
  });
  if (!res.ok) {
    throw new Error(`GitHub releases fetch returned ${res.status}`);
  }
  const releases = (await res.json()) as GitHubRelease[];

  const candidates = releases
    .filter((r) => !r.draft && !r.prerelease && r.tag_name.startsWith(TAG_PREFIX))
    .map((r) => ({ tag: r.tag_name, version: r.tag_name.slice(TAG_PREFIX.length), url: r.html_url }));

  if (candidates.length === 0) {
    logger.info({ event: "scanner_release_sync.no_releases" });
    return;
  }

  const latest = candidates.reduce((best, c) => (compareSemver(c.version, best.version) > 0 ? c : best));

  await db
    .updateTable("scanner_release_cache")
    .set({
      latest_version: latest.version,
      latest_tag: latest.tag,
      release_url: latest.url,
      synced_at: new Date(),
    })
    .where("id", "=", 1)
    .execute();

  logger.info({ event: "scanner_release_sync.completed", latest_version: latest.version, latest_tag: latest.tag });
}
