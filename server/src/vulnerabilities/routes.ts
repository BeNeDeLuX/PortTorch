import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

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
  }>`
    SELECT DISTINCT
      h.id AS host_id,
      h.ip AS host_ip,
      h.hostname AS host_hostname,
      chp.port AS port,
      cve_elem->>'id' AS cve_id,
      (cve_elem->>'cvssScore')::float AS cvss_score,
      cve_elem->>'cvssSeverity' AS cvss_severity,
      cve_elem->>'description' AS description
    FROM current_host_ports chp
    JOIN hosts h ON h.id = chp.host_id
    JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
    CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
    WHERE chp.state = 'open'
    ${restriction}
  `.execute(db);

  const sorted = rows.rows.slice().sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0));

  res.json(sorted);
}));
