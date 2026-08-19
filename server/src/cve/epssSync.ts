import { sql } from "kysely";
import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";
import { ANY_TRIAGE_STATE, cveNotTriaged } from "../findingTriage/sqlFilters";

// Unlike cve_cache (see sync.ts), EPSS scores genuinely change day to day -
// FIRST.org recomputes the underlying model daily - so this re-checks every
// cached CVE once a day rather than cve_cache's 7-day staleness window,
// even though both syncs otherwise run on the same 24h tick.
const SYNC_INTERVAL_MS = 24 * 60 * 60_000;
const STALE_AFTER_MS = 24 * 60 * 60_000;

// FIRST's own docs don't publish a hard rate limit for this endpoint (unlike
// NVD), but batching keeps this to a handful of requests even for a large
// distinct-CVE set, and the delay between batches is just good-citizen
// spacing, not a documented requirement.
const BATCH_SIZE = 100;
const BATCH_DELAY_MS = 250;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function startEpssSync(): void {
  tick().catch((err) => logger.error({ event: "epss_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "epss_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, SYNC_INTERVAL_MS);
}

async function tick(): Promise<void> {
  // cve_cache is already scoped to CPEs currently seen on open ports (see
  // cve/sync.ts) - reading the CVE ids back out of it, rather than
  // re-deriving from current_host_ports directly, means EPSS only ever
  // scores CVEs we already know are relevant to this fleet.
  const rows = await sql<{ cve_id: string }>`
    SELECT DISTINCT cve_elem->>'id' AS cve_id
    FROM cve_cache
    CROSS JOIN LATERAL jsonb_array_elements(cves) AS cve_elem
  `.execute(db);
  const seenCveIds = [...new Set(rows.rows.map((r) => r.cve_id))];
  if (seenCveIds.length === 0) return;

  const cached = await db
    .selectFrom("epss_cache")
    .select(["cve_id", "checked_at"])
    .where("cve_id", "in", seenCveIds)
    .execute();
  const checkedAtByCveId = new Map(cached.map((c) => [c.cve_id, c.checked_at]));

  const staleThreshold = Date.now() - STALE_AFTER_MS;
  const toRefresh = seenCveIds.filter((id) => {
    const checkedAt = checkedAtByCveId.get(id);
    return !checkedAt || new Date(checkedAt).getTime() < staleThreshold;
  });

  if (toRefresh.length > 0) {
    logger.info({ event: "epss_sync.started", cve_count: toRefresh.length });
    let synced = 0;
    let failed = 0;

    for (let i = 0; i < toRefresh.length; i += BATCH_SIZE) {
      const batch = toRefresh.slice(i, i + BATCH_SIZE);
      try {
        const scores = await fetchEpssForCves(batch);
        const now = new Date().toISOString();
        const rowsToUpsert = batch
          .filter((id) => scores.has(id))
          .map((id) => ({ cve_id: id, epss: scores.get(id)!.epss, percentile: scores.get(id)!.percentile, checked_at: now }));
        // A CVE with no EPSS entry (e.g. reserved/rejected in the model)
        // simply isn't upserted - leaves any prior cached value in place
        // rather than deleting it, same "don't erase a previously-captured
        // value on an inconclusive re-check" reasoning as the OS/MAC upserts.
        if (rowsToUpsert.length > 0) {
          await db
            .insertInto("epss_cache")
            .values(rowsToUpsert)
            .onConflict((oc) => oc.column("cve_id").doUpdateSet((eb) => ({ epss: eb.ref("excluded.epss"), percentile: eb.ref("excluded.percentile"), checked_at: eb.ref("excluded.checked_at") })))
            .execute();
        }
        synced += rowsToUpsert.length;
      } catch (err) {
        failed += batch.length;
        logger.warn({ event: "epss_sync.batch_failed", batch_size: batch.length, err: err instanceof Error ? err.message : String(err) });
      }
      await sleep(BATCH_DELAY_MS);
    }

    logger.info({ event: "epss_sync.completed", synced, failed });
  }

  // Runs every tick regardless of whether anything above needed a refresh
  // (not just inside the toRefresh branch) - a previous alert attempt that
  // failed to send, or a lowered EPSS_ALERT_THRESHOLD, should still get
  // picked up on the very next tick rather than waiting for the next score
  // change.
  await checkHighEpssAlerts().catch((err) =>
    logger.error({ event: "epss_sync.alert_check_failed", err: err instanceof Error ? err.message : String(err) })
  );
}

// Fires "vulnerability.high_epss" once per CVE the first time its cached
// score reaches config.epssAlertThreshold (alert_sent_at is never re-armed
// - see db/types.ts's EpssCacheTable - so a score oscillating around the
// threshold day to day can't spam repeated alerts for the same CVE).
// Exported so tests can exercise the alert-firing logic directly against a
// real database without going through tick()'s network-calling refresh
// loop (see epssAlert.integration.test.ts).
export async function checkHighEpssAlerts(): Promise<void> {
  const highScoring = await db
    .selectFrom("epss_cache")
    .select(["cve_id", "epss", "percentile"])
    .where("epss", ">=", config.epssAlertThreshold)
    .where("alert_sent_at", "is", null)
    .execute();
  if (highScoring.length === 0) return;

  for (const cve of highScoring) {
    // Which currently-open host+port pairs this specific CVE affects -
    // same cve_cache/current_host_ports join vulnerabilities/routes.ts
    // uses for the fleet-wide view, just filtered to one CVE id instead of
    // returned as one row per match.
    const affected = await sql<{ ip: string; hostname: string | null; port: number }>`
      SELECT DISTINCT h.ip AS ip, h.hostname AS hostname, chp.port AS port
      FROM current_host_ports chp
      JOIN hosts h ON h.id = chp.host_id
      JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
      CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
      WHERE chp.state = 'open' AND cve_elem->>'id' = ${cve.cve_id}
        -- A finding someone already triaged (false positive, accepted
        -- risk, or fixed) must not re-alert - re-paging on a decision
        -- that's already been made is the alert fatigue triage exists to
        -- prevent. Broader than the host list's risk indicator, which
        -- only drops false_positive/fixed (see sqlFilters.ts).
        AND ${cveNotTriaged("h.id", "cve_elem->>'id'", ANY_TRIAGE_STATE)}
    `.execute(db);

    // A cve_cache entry can outlive the port it was fingerprinted from
    // (the port closes, or the CPE simply stops appearing) - nothing to
    // alert about, but still mark it seen so it isn't rechecked forever.
    if (affected.rows.length === 0) {
      await db.updateTable("epss_cache").set({ alert_sent_at: new Date().toISOString() }).where("cve_id", "=", cve.cve_id).execute();
      continue;
    }

    const preview = affected.rows
      .slice(0, 5)
      .map((h) => `${h.hostname ? `${h.hostname} (${h.ip})` : h.ip}:${h.port}`)
      .join(", ");
    const more = affected.rows.length > 5 ? ` and ${affected.rows.length - 5} more` : "";
    const message = `${cve.cve_id} has an EPSS score of ${(cve.epss * 100).toFixed(1)}% (${Math.round(
      cve.percentile * 100
    )}th percentile, predicted exploit probability in the next 30 days) - affects ${affected.rows.length} host(s): ${preview}${more}`;

    await dispatchWebhook("vulnerability.high_epss", message, {
      cveId: cve.cve_id,
      epssScore: cve.epss,
      epssPercentile: cve.percentile,
      affectedHosts: affected.rows.map((h) => ({ ip: h.ip, hostname: h.hostname, port: h.port })),
    });

    await db.updateTable("epss_cache").set({ alert_sent_at: new Date().toISOString() }).where("cve_id", "=", cve.cve_id).execute();
    logger.info({ event: "epss_sync.high_epss_alerted", cve_id: cve.cve_id, epss: cve.epss, affected_hosts: affected.rows.length });
  }
}

async function fetchEpssForCves(cveIds: string[]): Promise<Map<string, { epss: number; percentile: number }>> {
  const url = `https://api.first.org/data/v1/epss?cve=${cveIds.map(encodeURIComponent).join(",")}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`EPSS API returned ${res.status}`);
  }
  const body = (await res.json()) as { data?: Array<{ cve: string; epss: string; percentile: string }> };
  const result = new Map<string, { epss: number; percentile: number }>();
  for (const entry of body.data ?? []) {
    result.set(entry.cve, { epss: parseFloat(entry.epss), percentile: parseFloat(entry.percentile) });
  }
  return result;
}
