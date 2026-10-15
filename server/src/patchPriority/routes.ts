import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { compareVersions, isComparableVersion, parseSysDescr } from "../lib/firmware";
import { NOT_A_LIVE_RISK_STATES, cveNotTriaged, cveRuleNotTriaged } from "../findingTriage/sqlFilters";

export const patchPriorityRouter = Router();
patchPriorityRouter.use(requireAuth);

// "What do we patch first?" - the raw signals per host, gathered from
// what the platform already knows: how long the device has been up (SNMP),
// its known CVEs (KEV first), and the software and firmware versions it
// runs, with the newest version of each product seen anywhere in the
// fleet. The ranking itself happens in the frontend
// (lib/patchPriority.ts), because upstream end of life - one of the
// signals - is derived there (lib/softwareLifecycle.ts) and kept there so
// a lapsed date reaches every host on the next deploy.
//
// CVE counts follow the host list's risk policy plus the fleet-wide
// rules, like the Software page: a false positive or a fixed finding is
// not current exposure, an accepted risk still is.

interface HostRow {
  id: string;
  ip: string;
  hostname: string | null;
  derived_hostname: string | null;
  scanner: string | null;
  boot_time: Date | null;
  uptime_source: string | null;
  uptime_observed_at: Date | null;
}

patchPriorityRouter.get(
  "/",
  asyncHandler(async (req, res) => {
    const allowed = getAllowedScannerAgentIds(req);
    const restriction = allowed ? sql`AND h.scanner_agent_id = ANY(${allowed}::uuid[])` : sql``;

    const [hosts, cves, products, firmware] = await Promise.all([
      sql<HostRow>`
        SELECT h.id, host(h.ip) AS ip, h.hostname, h.derived_hostname, sa.name AS scanner,
               h.boot_time, h.uptime_source, h.uptime_observed_at
        FROM hosts h LEFT JOIN scanner_agents sa ON sa.id = h.scanner_agent_id
        WHERE h.retired_at IS NULL ${restriction}
      `.execute(db),
      sql<{ host_id: string; cve_count: string; max_cvss: number | null; has_kev: boolean; kev_ids: string[] | null }>`
        SELECT chp.host_id,
               count(DISTINCT cve_elem->>'id') AS cve_count,
               max((cve_elem->>'cvssScore')::float) AS max_cvss,
               bool_or(kc.cve_id IS NOT NULL) AS has_kev,
               array_remove(array_agg(DISTINCT kc.cve_id), NULL) AS kev_ids
        FROM current_host_ports chp
        JOIN hosts h ON h.id = chp.host_id
        JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
        CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
        LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
        WHERE chp.state = 'open' AND h.retired_at IS NULL ${restriction}
          AND ${cveNotTriaged("h.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
          AND ${cveRuleNotTriaged("cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
        GROUP BY chp.host_id
      `.execute(db),
      sql<{ host_id: string; product: string; version: string | null }>`
        SELECT DISTINCT chp.host_id, chp.service_product AS product, nullif(btrim(coalesce(chp.service_version, '')), '') AS version
        FROM current_host_ports chp JOIN hosts h ON h.id = chp.host_id
        WHERE chp.state = 'open' AND h.retired_at IS NULL AND btrim(coalesce(chp.service_product, '')) <> '' ${restriction}
      `.execute(db),
      sql<{ host_id: string; output: string }>`
        SELECT chp.host_id, e->>'output' AS output
        FROM current_host_ports chp JOIN hosts h ON h.id = chp.host_id
        CROSS JOIN LATERAL jsonb_array_elements(chp.nse_extra) AS e
        WHERE chp.port = 161 AND chp.protocol = 'udp' AND chp.state = 'open' AND h.retired_at IS NULL
          AND chp.nse_extra IS NOT NULL AND e->>'id' = 'snmp-sysdescr' ${restriction}
      `.execute(db),
    ]);

    const software = new Map<string, Array<{ product: string; version: string | null; source: "service" | "snmp" }>>();
    const push = (hostId: string, entry: { product: string; version: string | null; source: "service" | "snmp" }) => {
      const list = software.get(hostId) ?? [];
      list.push(entry);
      software.set(hostId, list);
    };
    for (const p of products.rows) push(p.host_id, { product: p.product, version: p.version, source: "service" });
    for (const f of firmware.rows) {
      const fw = parseSysDescr(f.output ?? "");
      if (fw) push(f.host_id, { ...fw, source: "snmp" });
    }

    // The newest comparable version of each product anywhere in scope.
    const newest = new Map<string, string>();
    for (const list of software.values()) {
      for (const s of list) {
        if (!s.version || !isComparableVersion(s.version)) continue;
        const k = s.product.toLowerCase();
        const cur = newest.get(k);
        if (!cur || compareVersions(s.version, cur) > 0) newest.set(k, s.version);
      }
    }

    const cveBy = new Map(cves.rows.map((c) => [c.host_id, c]));
    const items = hosts.rows
      .map((h) => {
        const c = cveBy.get(h.id);
        const list = (software.get(h.id) ?? []).map((s) => {
          const top = newest.get(s.product.toLowerCase());
          const behind = top && s.version && isComparableVersion(s.version) && compareVersions(s.version, top) < 0 ? top : null;
          return { ...s, newerInFleet: behind };
        });
        return {
          id: h.id,
          ip: h.ip,
          hostname: h.hostname ?? h.derived_hostname,
          scanner: h.scanner,
          bootTime: h.boot_time,
          uptimeSource: h.uptime_source,
          uptimeObservedAt: h.uptime_observed_at,
          cveCount: c ? Number(c.cve_count) : 0,
          maxCvss: c?.max_cvss ?? null,
          kevIds: c?.kev_ids ?? [],
          software: list,
        };
      })
      // Only hosts carrying at least one signal; the rest have nothing to rank.
      .filter((h) => h.bootTime || h.cveCount > 0 || h.software.length > 0);

    res.json({ items });
  })
);
