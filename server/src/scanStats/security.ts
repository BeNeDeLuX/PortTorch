import { sql } from "kysely";
import { db } from "../db";
import { NOT_A_LIVE_RISK_STATES } from "../findingTriage/sqlFilters";
import type { Slice } from "./types";

// Severity order, worst first - fixed rather than by-size, for the same
// reason the port categories are: a severity keeps its colour and its
// place regardless of what a given fleet happens to contain.
const CVSS_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
const NUCLEI_SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;

// How many hosts the "most exposed" table lists. Long enough to act on,
// short enough that it stays a shortlist rather than a second host list.
const TOP_HOSTS = 10;

export interface SecurityStats {
  totals: {
    cveFindings: number;
    affectedHosts: number;
    kevFindings: number;
    kevHosts: number;
    ransomwareCves: number;
    webFindings: number;
  };
  cveSeverities: Slice[];
  epssBuckets: Slice[];
  nucleiSeverities: Slice[];
  topHosts: Array<{
    hostId: string;
    ip: string;
    hostname: string | null;
    cveCount: number;
    maxCvss: number | null;
    kevCount: number;
    webFindings: number;
  }>;
}

interface CveRow {
  host_id: string;
  ip: string;
  hostname: string | null;
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  epss_score: number | null;
  is_kev: boolean;
  ransomware: string | null;
}

function bucketEpss(score: number | null): string {
  if (score === null) return "No score yet";
  if (score >= 0.5) return "≥ 50%";
  if (score >= 0.1) return "10-50%";
  if (score >= 0.01) return "1-10%";
  return "< 1%";
}

const EPSS_BUCKET_ORDER = ["≥ 50%", "10-50%", "1-10%", "< 1%", "No score yet"];

/**
 * The security half of the Scan Stats page: how bad the fleet's currently
 * open findings are, rather than how many of them there are.
 *
 * Deliberately its own query and its own endpoint rather than more fields
 * on the composition stats: this one joins cve_cache and unnests a jsonb
 * array per port, which is the heaviest read in the app, while the other
 * is three grouped counts. Kept apart, a slow CVE cache can't make the
 * whole page slow to first paint.
 *
 * Counting matches the Vulnerabilities page's own notion of a finding:
 * one per (host, CVE), not per (host, port, CVE) - the same software on
 * three ports of one host is one thing to fix, and counting it three
 * times would make a handful of multi-homed services dominate every
 * chart on this page.
 */
export async function computeSecurityStats(
  allowedScannerAgentIds: string[] | null,
  filterScannerAgentIds: string[],
  hideRetired: boolean
): Promise<SecurityStats> {
  const hostWhere = sql`
    ${allowedScannerAgentIds ? sql`AND h.scanner_agent_id = ANY(${allowedScannerAgentIds})` : sql``}
    ${filterScannerAgentIds.length > 0 ? sql`AND h.scanner_agent_id = ANY(${filterScannerAgentIds})` : sql``}
    ${hideRetired ? sql`AND h.retired_at IS NULL` : sql``}
  `;

  const [cveRows, nucleiRows] = await Promise.all([
    // DISTINCT on the (host, CVE) pair, so the port multiplicity above is
    // collapsed in SQL rather than being counted and then divided out.
    sql<CveRow>`
      SELECT DISTINCT
        h.id AS host_id,
        host(h.ip) AS ip,
        h.hostname AS hostname,
        cve_elem->>'id' AS cve_id,
        (cve_elem->>'cvssScore')::float AS cvss_score,
        cve_elem->>'cvssSeverity' AS cvss_severity,
        ec.epss AS epss_score,
        (kc.cve_id IS NOT NULL) AS is_kev,
        kc.known_ransomware_campaign_use AS ransomware
      FROM current_host_ports chp
      JOIN hosts h ON h.id = chp.host_id
      JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
      CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
      LEFT JOIN epss_cache ec ON ec.cve_id = cve_elem->>'id'
      LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
      WHERE chp.state = 'open'
        ${hostWhere}
        -- Same policy as the host list's own risk indicator, via the same
        -- shared state list: a false positive or a fixed finding is not
        -- current exposure, while an accepted risk still is. Fleet rules
        -- count too - a CVE dismissed fleet-wide is dismissed here.
        AND NOT EXISTS (
          SELECT 1 FROM finding_triage ft
          WHERE ft.kind = 'cve' AND ft.host_id = h.id AND ft.cve_id = cve_elem->>'id'
            AND ft.state = ANY(${[...NOT_A_LIVE_RISK_STATES]})
            AND (ft.review_at IS NULL OR ft.review_at > now())
        )
        AND NOT EXISTS (
          SELECT 1 FROM finding_triage_rules ftr
          WHERE ftr.kind = 'cve' AND ftr.cve_id = cve_elem->>'id'
            AND ftr.state = ANY(${[...NOT_A_LIVE_RISK_STATES]})
        )
    `.execute(db),

    // Same (host, template, matched_at) identity the Web Findings page
    // dedups on - nuclei_findings gets a fresh row per observation, so
    // counting rows would count rescans.
    sql<{ host_id: string; severity: string | null }>`
      SELECT DISTINCT ON (nf.host_id, nf.template_id, nf.matched_at)
        nf.host_id, nf.severity
      FROM nuclei_findings nf
      JOIN hosts h ON h.id = nf.host_id
      WHERE true
        ${hostWhere}
        AND NOT EXISTS (
          SELECT 1 FROM finding_triage ft
          WHERE ft.kind = 'nuclei' AND ft.host_id = nf.host_id
            AND ft.template_id = nf.template_id AND ft.matched_at = nf.matched_at
            AND ft.state = ANY(${[...NOT_A_LIVE_RISK_STATES]})
            AND (ft.review_at IS NULL OR ft.review_at > now())
        )
        AND NOT EXISTS (
          SELECT 1 FROM finding_triage_rules ftr
          WHERE ftr.kind = 'nuclei' AND ftr.template_id = nf.template_id
            AND ftr.state = ANY(${[...NOT_A_LIVE_RISK_STATES]})
        )
      ORDER BY nf.host_id, nf.template_id, nf.matched_at, nf.observed_at DESC
    `.execute(db),
  ]);

  const severityCounts = new Map<string, number>();
  const epssCounts = new Map<string, number>();
  const affectedHosts = new Set<string>();
  const kevHosts = new Set<string>();
  const ransomwareCves = new Set<string>();
  let kevFindings = 0;

  interface HostAgg {
    hostId: string;
    ip: string;
    hostname: string | null;
    cveCount: number;
    maxCvss: number | null;
    kevCount: number;
    webFindings: number;
  }
  const byHost = new Map<string, HostAgg>();

  for (const row of cveRows.rows) {
    // An entry with no CVSS metric at all is its own slice rather than
    // being dropped - "we know about this CVE but not how bad it is" is a
    // real state (NVD publishes plenty of them), and dropping it would
    // make the severity chart quietly disagree with the finding total.
    const severity = (row.cvss_severity ?? "").toUpperCase();
    const label = (CVSS_SEVERITIES as readonly string[]).includes(severity) ? severity : "UNKNOWN";
    severityCounts.set(label, (severityCounts.get(label) ?? 0) + 1);

    const bucket = bucketEpss(row.epss_score === null ? null : Number(row.epss_score));
    epssCounts.set(bucket, (epssCounts.get(bucket) ?? 0) + 1);

    affectedHosts.add(row.host_id);
    if (row.is_kev) {
      kevFindings++;
      kevHosts.add(row.host_id);
      // CISA records this as the string "Known"/"Unknown" rather than a
      // boolean, so anything but an explicit "known" is treated as not
      // confirmed.
      if ((row.ransomware ?? "").toLowerCase() === "known") ransomwareCves.add(row.cve_id);
    }

    const agg = byHost.get(row.host_id) ?? {
      hostId: row.host_id,
      ip: String(row.ip),
      hostname: row.hostname,
      cveCount: 0,
      maxCvss: null,
      kevCount: 0,
      webFindings: 0,
    };
    agg.cveCount++;
    const score = row.cvss_score === null ? null : Number(row.cvss_score);
    if (score !== null && (agg.maxCvss === null || score > agg.maxCvss)) agg.maxCvss = score;
    if (row.is_kev) agg.kevCount++;
    byHost.set(row.host_id, agg);
  }

  const nucleiCounts = new Map<string, number>();
  for (const row of nucleiRows.rows) {
    const severity = (row.severity ?? "unknown").toLowerCase();
    const label = (NUCLEI_SEVERITIES as readonly string[]).includes(severity) ? severity : "unknown";
    nucleiCounts.set(label, (nucleiCounts.get(label) ?? 0) + 1);
    const agg = byHost.get(row.host_id);
    if (agg) agg.webFindings++;
  }

  // KEV first, then CVSS, then sheer count - the same precedence the
  // Vulnerabilities list already sorts by, so "most exposed" means the
  // same thing on both pages.
  const topHosts = [...byHost.values()]
    .sort(
      (a, b) =>
        b.kevCount - a.kevCount ||
        (b.maxCvss ?? 0) - (a.maxCvss ?? 0) ||
        b.cveCount - a.cveCount ||
        a.ip.localeCompare(b.ip)
    )
    .slice(0, TOP_HOSTS);

  return {
    totals: {
      cveFindings: cveRows.rows.length,
      affectedHosts: affectedHosts.size,
      kevFindings,
      kevHosts: kevHosts.size,
      ransomwareCves: ransomwareCves.size,
      webFindings: nucleiRows.rows.length,
    },
    cveSeverities: CVSS_SEVERITIES.filter((s) => (severityCounts.get(s) ?? 0) > 0).map((s) => ({
      label: s.charAt(0) + s.slice(1).toLowerCase(),
      value: severityCounts.get(s) ?? 0,
    })),
    epssBuckets: EPSS_BUCKET_ORDER.filter((b) => (epssCounts.get(b) ?? 0) > 0).map((b) => ({
      label: b,
      value: epssCounts.get(b) ?? 0,
    })),
    nucleiSeverities: NUCLEI_SEVERITIES.filter((s) => (nucleiCounts.get(s) ?? 0) > 0).map((s) => ({
      label: s.charAt(0).toUpperCase() + s.slice(1),
      value: nucleiCounts.get(s) ?? 0,
    })),
    topHosts,
  };
}
