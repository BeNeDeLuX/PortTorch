import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";

// CISA publishes this as a single bulk JSON file, not a per-CVE lookup API
// like EPSS's - there's no rate limit or API key to worry about, and no
// batching is needed, just one GET per sync. Same 24h cadence as
// cve/sync.ts and cve/epssSync.ts for consistency, even though CISA has
// no documented update schedule of its own.
const SYNC_INTERVAL_MS = 24 * 60 * 60_000;

const CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevCatalogEntry {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

interface KevCatalog {
  vulnerabilities: KevCatalogEntry[];
}

export function startKevSync(): void {
  tick().catch((err) => logger.error({ event: "kev_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "kev_sync.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, SYNC_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const res = await fetch(CATALOG_URL);
  if (!res.ok) {
    throw new Error(`CISA KEV catalog fetch returned ${res.status}`);
  }
  const catalog = (await res.json()) as KevCatalog;
  const entries = catalog.vulnerabilities ?? [];

  if (entries.length > 0) {
    // Upsert every entry, but never touch alert_sent_at on conflict - same
    // "don't erase a previously-captured value on a routine re-check"
    // reasoning as epss_cache's own upsert (see epssSync.ts). CISA's
    // catalog is authoritative and complete on every fetch, so unlike
    // EPSS (which only ever refreshes CVEs already relevant to this
    // fleet), every KEV entry gets upserted regardless of whether it
    // matches anything currently scanned - the fleet-relevance filtering
    // happens later, in checkKevAlerts, same as it does in the fleet-wide
    // Vulnerabilities view.
    const rows = entries.map((e) => ({
      cve_id: e.cveID,
      vendor_project: e.vendorProject ?? null,
      product: e.product ?? null,
      vulnerability_name: e.vulnerabilityName ?? null,
      date_added: e.dateAdded ?? null,
      due_date: e.dueDate ?? null,
      known_ransomware_campaign_use: e.knownRansomwareCampaignUse ?? null,
      synced_at: new Date().toISOString(),
    }));
    await db
      .insertInto("kev_cache")
      .values(rows)
      .onConflict((oc) =>
        oc.column("cve_id").doUpdateSet((eb) => ({
          vendor_project: eb.ref("excluded.vendor_project"),
          product: eb.ref("excluded.product"),
          vulnerability_name: eb.ref("excluded.vulnerability_name"),
          date_added: eb.ref("excluded.date_added"),
          due_date: eb.ref("excluded.due_date"),
          known_ransomware_campaign_use: eb.ref("excluded.known_ransomware_campaign_use"),
          synced_at: eb.ref("excluded.synced_at"),
        }))
      )
      .execute();

    // CISA does occasionally delist a CVE (rare, but it happens) - unlike
    // cve_cache/epss_cache, which only ever grow or get individually
    // refreshed, kev_cache is meant to mirror the catalog's current
    // complete state, so a row whose cve_id no longer appears in this
    // fetch is removed rather than left stale forever.
    const currentIds = entries.map((e) => e.cveID);
    await db.deleteFrom("kev_cache").where("cve_id", "not in", currentIds).execute();

    logger.info({ event: "kev_sync.completed", entries: entries.length });
  }

  await checkKevAlerts().catch((err) =>
    logger.error({ event: "kev_sync.alert_check_failed", err: err instanceof Error ? err.message : String(err) })
  );
}

// Fires "vulnerability.kev" once per CVE the first time it's found to
// affect a currently open port - alert_sent_at is never re-armed, mirrors
// checkHighEpssAlerts in every respect except the triggering condition
// (KEV membership itself, not a numeric threshold - a CVE is either known
// to be actively exploited or it isn't). Exported for the same testing
// reason checkHighEpssAlerts is.
export async function checkKevAlerts(): Promise<void> {
  const unalerted = await db
    .selectFrom("kev_cache")
    .select(["cve_id", "vulnerability_name", "known_ransomware_campaign_use"])
    .where("alert_sent_at", "is", null)
    .execute();
  if (unalerted.length === 0) return;

  for (const kev of unalerted) {
    // Same cve_cache/current_host_ports join checkHighEpssAlerts and
    // vulnerabilities/routes.ts both already use, filtered to one CVE id.
    const affected = await sql<{ ip: string; hostname: string | null; port: number }>`
      SELECT DISTINCT h.ip AS ip, h.hostname AS hostname, chp.port AS port
      FROM current_host_ports chp
      JOIN hosts h ON h.id = chp.host_id
      JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
      CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
      WHERE chp.state = 'open' AND cve_elem->>'id' = ${kev.cve_id}
    `.execute(db);

    // Not relevant to this fleet (yet) - still mark it seen, same
    // "inconclusive re-check" reasoning as checkHighEpssAlerts, so it
    // isn't re-evaluated forever; if it later matches a newly-discovered
    // port, that's a fresh row insert elsewhere, not a re-alert path here.
    if (affected.rows.length === 0) {
      await db.updateTable("kev_cache").set({ alert_sent_at: new Date().toISOString() }).where("cve_id", "=", kev.cve_id).execute();
      continue;
    }

    const preview = affected.rows
      .slice(0, 5)
      .map((h) => `${h.hostname ? `${h.hostname} (${h.ip})` : h.ip}:${h.port}`)
      .join(", ");
    const more = affected.rows.length > 5 ? ` and ${affected.rows.length - 5} more` : "";
    const ransomwareNote = kev.known_ransomware_campaign_use === "Known" ? " - known ransomware campaign use" : "";
    const message = `${kev.cve_id}${kev.vulnerability_name ? ` (${kev.vulnerability_name})` : ""} is on CISA's Known Exploited Vulnerabilities catalog${ransomwareNote} - affects ${affected.rows.length} host(s): ${preview}${more}`;

    await dispatchWebhook("vulnerability.kev", message, {
      cveId: kev.cve_id,
      vulnerabilityName: kev.vulnerability_name,
      knownRansomwareCampaignUse: kev.known_ransomware_campaign_use,
      affectedHosts: affected.rows.map((h) => ({ ip: h.ip, hostname: h.hostname, port: h.port })),
    });

    await db.updateTable("kev_cache").set({ alert_sent_at: new Date().toISOString() }).where("cve_id", "=", kev.cve_id).execute();
    logger.info({ event: "kev_sync.kev_alerted", cve_id: kev.cve_id, affected_hosts: affected.rows.length });
  }
}
