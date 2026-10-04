import { sql } from "kysely";
import { recordAudit } from "../audit/log";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings } from "../settings/appSettings";
import { compareSemver } from "./githubSync";
import { requestScannerUpdate } from "./requestUpdate";

const CHECK_INTERVAL_MS = 5 * 60 * 1000;

// The same "looks like it is running in serve mode right now" heuristic
// the Scanner Agents page gates its Update button on: only serve mode runs
// the update watcher, and every one of its polls refreshes last_seen_at.
const RECENTLY_SEEN_MS = 5 * 60 * 1000;

export interface AutoUpdateRequest {
  scannerAgentId: string;
  name: string;
  fromVersion: string;
  toVersion: string;
}

export interface CanaryStatus {
  id: string;
  name: string;
  version: string | null;
  // Reports the latest release (or newer).
  onLatest: boolean;
  // Has completed a scan that started after it began reporting that
  // version - the evidence the release actually works there.
  provenOnLatest: boolean;
}

// Whether the rest of the fleet may take `latest` yet.
//   none    - no canary is marked, so everyone updates at once (the
//             behaviour before canaries existed).
//   open    - a canary has completed a scan on the release.
//   waiting - canaries exist and none has proven the release yet.
export type CanaryGate = "none" | "open" | "waiting";

export interface AutoUpdateStatus {
  fleetDefault: boolean;
  latestVersion: string | null;
  gate: CanaryGate;
  canaries: CanaryStatus[];
}

async function canaryStatus(latest: string | null): Promise<{ gate: CanaryGate; canaries: CanaryStatus[] }> {
  const rows = await db
    .selectFrom("scanner_agents as sa")
    .select([
      "sa.id",
      "sa.name",
      "sa.version",
      // A scan that started on the current version and finished cleanly.
      // Started, not finished, after the version change: a scan already
      // running when the binary was replaced ran on the old one.
      sql<boolean>`EXISTS (
        SELECT 1 FROM scan_jobs sj
        WHERE sj.scanner_agent_id = sa.id
          AND sj.status = 'completed'
          AND sa.version_changed_at IS NOT NULL
          AND sj.started_at >= sa.version_changed_at
      )`.as("scanned_since_change"),
    ])
    .where("sa.update_canary", "=", true)
    .where("sa.revoked_at", "is", null)
    .orderBy("sa.name")
    .execute();

  const canaries = rows.map((r) => {
    const onLatest = Boolean(latest && r.version && compareSemver(r.version, latest) >= 0);
    return { id: r.id, name: r.name, version: r.version, onLatest, provenOnLatest: onLatest && r.scanned_since_change };
  });
  const gate: CanaryGate = canaries.length === 0 ? "none" : canaries.some((c) => c.provenOnLatest) ? "open" : "waiting";
  return { gate, canaries };
}

async function latestRelease(): Promise<string | null> {
  const release = await db
    .selectFrom("scanner_release_cache")
    .select("latest_version")
    .where("id", "=", 1)
    .executeTakeFirst();
  return release?.latest_version ?? null;
}

export async function getAutoUpdateStatus(): Promise<AutoUpdateStatus> {
  const latestVersion = await latestRelease();
  const { scannerAutoUpdate } = await getAppSettings();
  return { fleetDefault: scannerAutoUpdate, latestVersion, ...(await canaryStatus(latestVersion)) };
}

// Requests the self-update an admin would otherwise have to click, for
// every scanner whose effective auto-update setting is on and which is
// behind the latest published release. It only ever *sets the flag*: the
// scanner applies it through the existing watcher, which already waits for
// idle - an update never interrupts a running scan.
//
// A scanner with any update state at all is left alone. 'pending' is
// already on its way; 'failed' is the terminal state after three attempts,
// and re-requesting it here would turn "needs an admin to look at it" into
// a retry loop every five minutes. That state clears either when an admin
// re-triggers it or when the scanner reports the latest version (see
// apiKeyAuth.ts), after which auto-update covers it again.
//
// Staggered when any canary is marked: canaries go first, everyone else
// waits until a canary has completed a scan on the new release. Only the
// automatic path is held back - an admin's Update click is never gated.
export async function runScannerAutoUpdate(now: Date = new Date()): Promise<AutoUpdateRequest[]> {
  const latest = await latestRelease();
  if (!latest) return [];

  const { scannerAutoUpdate } = await getAppSettings();
  const { gate } = await canaryStatus(latest);
  let query = db
    .selectFrom("scanner_agents")
    .select(["id", "name", "version"])
    .where("revoked_at", "is", null)
    .where("update_request_status", "is", null)
    .where("update_requested_at", "is", null)
    .where("version", "is not", null)
    .where("last_seen_at", ">", new Date(now.getTime() - RECENTLY_SEEN_MS))
    .where(sql<boolean>`coalesce(auto_update, ${scannerAutoUpdate})`);
  if (gate === "waiting") query = query.where("update_canary", "=", true);
  const candidates = await query.execute();

  const requested: AutoUpdateRequest[] = [];
  for (const agent of candidates) {
    if (!agent.version || compareSemver(latest, agent.version) <= 0) continue;
    const outcome = await requestScannerUpdate(agent.id);
    // A 409 here means an admin (or a concurrent tick) got there first,
    // which is the outcome either way.
    if (!outcome.ok) continue;
    logger.info({
      event: "agent.auto_update_requested",
      scanner_agent_id: agent.id,
      scanner_agent_name: agent.name,
      from_version: agent.version,
      to_version: latest,
      canary_gate: gate,
    });
    await recordAudit("agent.update_requested", "auto-update", undefined, {
      scanner_agent_id: agent.id,
      from_version: agent.version,
      to_version: latest,
    });
    requested.push({ scannerAgentId: agent.id, name: agent.name, fromVersion: agent.version, toVersion: latest });
  }
  return requested;
}

export function startScannerAutoUpdate(): void {
  const tick = () =>
    runScannerAutoUpdate().catch((err) =>
      logger.error({ event: "scanner_auto_update.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  setInterval(tick, CHECK_INTERVAL_MS);
}
