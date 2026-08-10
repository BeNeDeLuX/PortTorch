import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { toDateOnlyString } from "../lib/dateOnly";

export const vulnerabilitiesRouter = Router();
vulnerabilitiesRouter.use(requireAuth);

// Fleet-wide view across all hosts, not just a single host's detail page -
// same cve_cache lookup as the per-host port list in search/routes.ts,
// just unnested into one row per host+port+CVE instead of grouped per
// port. Raw SQL since Kysely has no jsonb/array builder helpers for the
// cpes-array-to-cve_cache join and jsonb_array_elements unnest.
vulnerabilitiesRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  const restriction = allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``;
  const rows = await sql<{
    host_id: string;
    host_ip: string;
    host_hostname: string | null;
    port: number;
    cve_id: string;
    cvss_score: number | null;
    cvss_severity: string | null;
    description: string;
    epss_score: number | null;
    epss_percentile: number | null;
    // node-postgres returns a `date` column as a JS Date, not the plain
    // string the type name suggests - see lib/dateOnly.ts's
    // toDateOnlyString, applied below before this ever reaches res.json.
    kev_date_added: Date | string | null;
    kev_known_ransomware_campaign_use: string | null;
  }>`
    SELECT DISTINCT
      h.id AS host_id,
      h.ip AS host_ip,
      h.hostname AS host_hostname,
      chp.port AS port,
      cve_elem->>'id' AS cve_id,
      (cve_elem->>'cvssScore')::float AS cvss_score,
      cve_elem->>'cvssSeverity' AS cvss_severity,
      cve_elem->>'description' AS description,
      ec.epss AS epss_score,
      ec.percentile AS epss_percentile,
      kc.date_added AS kev_date_added,
      kc.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use
    FROM current_host_ports chp
    JOIN hosts h ON h.id = chp.host_id
    JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
    CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
    -- Left, not inner: a CVE without a cached EPSS score yet (sync hasn't
    -- caught up, or FIRST has no entry for it) still needs to show up here,
    -- same "absence isn't an error" reasoning as a 404 from NVD itself.
    LEFT JOIN epss_cache ec ON ec.cve_id = cve_elem->>'id'
    -- Left, not inner, for the same reason - most CVEs are never added to
    -- CISA's KEV catalog at all, which is the normal case, not an error.
    LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
    WHERE chp.state = 'open'
    ${restriction}
  `.execute(db);

  // KEV membership is a stronger, more concrete signal than either CVSS
  // (severity, not likelihood) or EPSS (a predicted probability) - CISA
  // has confirmed active exploitation - so it sorts ahead of CVSS score
  // rather than being folded into the same sort key.
  const sorted = rows.rows
    .map((r) => ({ ...r, kev_date_added: toDateOnlyString(r.kev_date_added) }))
    .sort((a, b) => {
      const aKev = a.kev_date_added ? 1 : 0;
      const bKev = b.kev_date_added ? 1 : 0;
      if (aKev !== bKev) return bKev - aKev;
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    });

  res.json(sorted);
}));
