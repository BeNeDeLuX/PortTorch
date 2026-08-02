import { sql } from "kysely";
import { db } from "../db";
import { config } from "../config";
import { logger } from "../logger";
import { cpe22to23 } from "./cpe";
import type { CveEntry } from "../db/types";

// Daily is plenty - CVE data doesn't change minute to minute, and NVD's
// public rate limit (5 req/30s without a key, 50/30s with one) makes
// frequent full syncs impractical anyway. Runs once at startup too so a
// fresh deployment doesn't wait a full day for its first data.
const SYNC_INTERVAL_MS = 24 * 60 * 60_000;
// Re-check a cached CPE after this long, rather than on every sync -
// most CPEs seen in a scan keep reappearing scan after scan, and
// re-querying NVD for the same unchanged CPE daily would burn through
// the rate limit for no new information.
const STALE_AFTER_MS = 7 * 24 * 60 * 60_000;

function rateLimitDelayMs(): number {
  // Comfortably under NVD's published limits either way.
  return config.nvdApiKey ? 700 : 6500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function startCveSync(): void {
  tick().catch((err) => logger.error({ event: "cve_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "cve_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, SYNC_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const rows = await sql<{ cpe: string }>`
    SELECT DISTINCT unnest(cpes) AS cpe
    FROM current_host_ports
    WHERE cpes IS NOT NULL AND state = 'open'
  `.execute(db);
  const seenCpes = [...new Set(rows.rows.map((r) => r.cpe))];
  if (seenCpes.length === 0) return;

  const cached = await db
    .selectFrom("cve_cache")
    .select(["cpe", "checked_at"])
    .where("cpe", "in", seenCpes)
    .execute();
  const checkedAtByCpe = new Map(cached.map((c) => [c.cpe, c.checked_at]));

  const staleThreshold = Date.now() - STALE_AFTER_MS;
  const toRefresh = seenCpes.filter((cpe) => {
    const checkedAt = checkedAtByCpe.get(cpe);
    return !checkedAt || new Date(checkedAt).getTime() < staleThreshold;
  });
  if (toRefresh.length === 0) return;

  logger.info({ event: "cve_sync.started", cpe_count: toRefresh.length });
  let synced = 0;
  let failed = 0;

  for (const cpe of toRefresh) {
    try {
      const cves = await fetchCvesForCpe(cpe);
      await db
        .insertInto("cve_cache")
        .values({ cpe, cves: JSON.stringify(cves), checked_at: new Date().toISOString() })
        .onConflict((oc) => oc.column("cpe").doUpdateSet({ cves: JSON.stringify(cves), checked_at: new Date().toISOString() }))
        .execute();
      synced++;
    } catch (err) {
      failed++;
      logger.warn({ event: "cve_sync.cpe_failed", cpe, err: err instanceof Error ? err.message : String(err) });
    }
    await sleep(rateLimitDelayMs());
  }

  logger.info({ event: "cve_sync.completed", synced, failed });
}

async function fetchCvesForCpe(cpe22: string): Promise<CveEntry[]> {
  const cpe23 = cpe22to23(cpe22);
  if (!cpe23) return [];

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe23)}&resultsPerPage=20`;
  const res = await fetch(url, {
    headers: config.nvdApiKey ? { apiKey: config.nvdApiKey } : {},
  });
  // NVD returns 404 for a well-formed but non-existent CPE, which is the
  // normal case for a versionless CPE (e.g. cpe:/a:golang:go with no
  // version nmap could determine) - there's no exact dictionary entry to
  // match, not an error worth retrying/warning about.
  if (res.status === 404) return [];
  if (!res.ok) {
    throw new Error(`NVD API returned ${res.status} for ${cpe23}`);
  }
  interface CvssMetric {
    cvssData: { baseScore: number; baseSeverity?: string };
    baseSeverity?: string; // CVSS v2 puts it here instead of inside cvssData
  }
  const body = (await res.json()) as {
    vulnerabilities?: Array<{
      cve: {
        id: string;
        descriptions?: Array<{ lang: string; value: string }>;
        published?: string;
        metrics?: {
          cvssMetricV31?: CvssMetric[];
          cvssMetricV30?: CvssMetric[];
          cvssMetricV2?: CvssMetric[];
        };
      };
    }>;
  };

  return (body.vulnerabilities ?? []).map(({ cve }) => {
    const metric = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0] ?? cve.metrics?.cvssMetricV2?.[0];
    return {
      id: cve.id,
      description: cve.descriptions?.find((d) => d.lang === "en")?.value ?? "",
      cvssScore: metric?.cvssData?.baseScore ?? null,
      cvssSeverity: metric?.cvssData?.baseSeverity ?? metric?.baseSeverity ?? null,
      published: cve.published ?? null,
    };
  });
}
