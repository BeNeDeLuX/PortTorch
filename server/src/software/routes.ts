import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { limitFindings } from "../lib/findingLimit";
import { NOT_A_LIVE_RISK_STATES, cveNotTriaged, cveRuleNotTriaged } from "../findingTriage/sqlFilters";

export const softwareRouter = Router();
softwareRouter.use(requireAuth);

/**
 * Where a row was observed. The three answer with very different
 * confidence, and the page says which, because presenting a page's own
 * title as though it were a fingerprint would be a lie:
 *
 *  - "service": nmap's service probe on an open port. The strongest of
 *    the three, and the only one carrying a CPE and therefore CVEs.
 *  - "web": gowitness's technology fingerprint of the page served.
 *    Identifies real applications and frameworks, often with a version.
 *  - "title": the page's HTML <title>, verbatim. Not an identifier at
 *    all - but it is the only place many self-hosted applications
 *    (Grafana, Portainer, Home Assistant) appear at all, so leaving it
 *    out would hide exactly the software people go looking for.
 */
export type SoftwareSource = "service" | "web" | "title";

export interface SoftwareRow {
  product: string;
  /** Null when the version could not be determined. */
  version: string | null;
  /** Every source that saw it - see SoftwareSource. */
  sources: SoftwareSource[];
  hosts: number;
  ports: number;
  /** Which scanners see it - a fleet with several can run the same product in unrelated networks. */
  scanners: string[];
  firstSeen: string;
  lastSeen: string;
  cveCount: number;
  maxCvssScore: number | null;
  hasKev: boolean;
}

interface CountRow {
  product: string;
  version: string | null;
  hosts: string | number;
  ports: string | number;
  scanners: string[] | null;
  first_seen: Date | string;
  last_seen: Date | string;
}

interface WebRow {
  /** A gowitness technology ("Name" or "Name:Version"), or a page title. */
  value: string;
  hosts: string | number;
  ports: string | number;
  scanners: string[] | null;
  first_seen: Date | string;
  last_seen: Date | string;
}

interface CveRow {
  product: string;
  version: string | null;
  cve_count: string | number;
  max_cvss: number | null;
  has_kev: boolean | null;
}

// Case-insensitive and unambiguous, so nmap's "nginx" and gowitness's
// "Nginx" become one row carrying both sources rather than two rows for
// the same software. JSON.stringify rather than a separator character,
// which a product name could always contain.
const key = (product: string, version: string | null) =>
  JSON.stringify([product.toLowerCase(), (version ?? "").toLowerCase()]);

/**
 * gowitness reports a technology as "Name" or "Name:Version" - the same
 * thing nmap splits across a product and a version field, in one string.
 *
 * Split on the LAST colon, since a name may contain one while a version
 * may not, and only when what follows actually looks like a version.
 * Otherwise a name that merely contains a colon would silently lose half
 * of itself to a mis-split.
 */
export function splitTechnology(value: string): { product: string; version: string | null } {
  const trimmed = value.trim();
  const at = trimmed.lastIndexOf(":");
  if (at <= 0 || at === trimmed.length - 1) return { product: trimmed, version: null };
  const version = trimmed.slice(at + 1).trim();
  if (!/^\d[\w.+-]*$/.test(version)) return { product: trimmed, version: null };
  return { product: trimmed.slice(0, at).trim(), version };
}

// The fleet's software inventory: one row per (product, version), which
// is the unit you actually patch. Scan Stats already charts the same
// underlying data, but a donut answers "what is the shape of this" and
// not "which versions are out there, on how many hosts each, and which of
// them have known CVEs" - the question that turns into a work list.
//
// Identity is deliberately product plus version rather than product
// alone. "We run Samba" is not actionable; "we run Samba 4.17.2 on 40
// hosts and 4.22.10 on 3" is. A version that could not be determined
// keeps its own row rather than being folded into a neighbouring one -
// "we do not know which version these are" is a real and separately
// actionable state, not a rounding error.
softwareRouter.get(
  "/",
  asyncHandler(async (req, res) => {
    const allowed = getAllowedScannerAgentIds(req);
    const restriction = allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``;

    // Four queries rather than one, merged below on (product, version).
    // The CVE half joins cve_cache and unnests a jsonb array per port,
    // which fans a single port row out into one row per CVE - folding it
    // into the counting query would inflate the port count and force
    // every aggregate through a DISTINCT to compensate. Same "separate
    // rather than joined" reasoning Scan History documents for its
    // screenshot counts. The two web halves are separate for the plainer
    // reason that they read a different table.
    const [counts, technologies, titles, cves] = await Promise.all([
      sql<CountRow>`
        SELECT
          chp.service_product AS product,
          -- '' and NULL both mean "no version" and must not become two
          -- separate rows for the same software.
          nullif(btrim(coalesce(chp.service_version, '')), '') AS version,
          count(DISTINCT chp.host_id) AS hosts,
          count(DISTINCT (chp.host_id, chp.port, chp.protocol)) AS ports,
          array_remove(array_agg(DISTINCT sa.name), NULL) AS scanners,
          min(chp.observed_at) AS first_seen,
          max(chp.observed_at) AS last_seen
        FROM current_host_ports chp
        JOIN hosts h ON h.id = chp.host_id
        LEFT JOIN scanner_agents sa ON sa.id = h.scanner_agent_id
        WHERE chp.state = 'open'
          AND chp.service_product IS NOT NULL
          AND btrim(chp.service_product) <> ''
          ${restriction}
        GROUP BY 1, 2
      `.execute(db),

      // Newest capture per (host, port), the same identity the screenshot
      // gallery uses - a host scanned ten times has ten rows for one page,
      // and counting those would report captures rather than hosts.
      sql<WebRow>`
        WITH newest AS (
          SELECT DISTINCT ON (s.host_id, s.port)
                 s.host_id, s.port, s.technologies, s.captured_at, h.scanner_agent_id
          FROM screenshots s
          JOIN hosts h ON h.id = s.host_id
          WHERE true ${restriction}
          ORDER BY s.host_id, s.port, s.captured_at DESC
        )
        SELECT
          t AS value,
          count(DISTINCT newest.host_id) AS hosts,
          count(DISTINCT (newest.host_id, newest.port)) AS ports,
          array_remove(array_agg(DISTINCT sa.name), NULL) AS scanners,
          min(newest.captured_at) AS first_seen,
          max(newest.captured_at) AS last_seen
        FROM newest
        CROSS JOIN LATERAL unnest(newest.technologies) AS t
        LEFT JOIN scanner_agents sa ON sa.id = newest.scanner_agent_id
        WHERE btrim(t) <> ''
        GROUP BY 1
      `.execute(db),

      sql<WebRow>`
        WITH newest AS (
          SELECT DISTINCT ON (s.host_id, s.port)
                 s.host_id, s.port, s.page_title, s.captured_at, h.scanner_agent_id
          FROM screenshots s
          JOIN hosts h ON h.id = s.host_id
          WHERE true ${restriction}
          ORDER BY s.host_id, s.port, s.captured_at DESC
        )
        SELECT
          btrim(newest.page_title) AS value,
          count(DISTINCT newest.host_id) AS hosts,
          count(DISTINCT (newest.host_id, newest.port)) AS ports,
          array_remove(array_agg(DISTINCT sa.name), NULL) AS scanners,
          min(newest.captured_at) AS first_seen,
          max(newest.captured_at) AS last_seen
        FROM newest
        LEFT JOIN scanner_agents sa ON sa.id = newest.scanner_agent_id
        WHERE btrim(coalesce(newest.page_title, '')) <> ''
        GROUP BY 1
      `.execute(db),

      sql<CveRow>`
        SELECT
          chp.service_product AS product,
          nullif(btrim(coalesce(chp.service_version, '')), '') AS version,
          count(DISTINCT cve_elem->>'id') AS cve_count,
          max((cve_elem->>'cvssScore')::float) AS max_cvss,
          bool_or(kc.cve_id IS NOT NULL) AS has_kev
        FROM current_host_ports chp
        JOIN hosts h ON h.id = chp.host_id
        JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
        CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
        -- Left, not inner: most CVEs are never KEV-listed, which is the
        -- normal case rather than a reason to drop the row.
        LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
        WHERE chp.state = 'open'
          AND chp.service_product IS NOT NULL
          AND btrim(chp.service_product) <> ''
          ${restriction}
          -- The host list's risk-indicator policy, via the shared
          -- predicates: a false positive or a fixed finding is not
          -- current exposure, an accepted risk still is. Fleet-wide
          -- rules count too.
          AND ${cveNotTriaged("h.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
          AND ${cveRuleNotTriaged("cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
        GROUP BY 1, 2
      `.execute(db),
    ]);

    // Merged rather than concatenated: nmap and gowitness both see nginx
    // 1.30.3 on the same host, and two rows for it would overstate the
    // inventory and split its host count in half. Counts are taken as the
    // maximum across sources rather than summed, for the same reason -
    // they are two observations of one thing, not two things.
    const merged = new Map<string, SoftwareRow>();
    const add = (
      source: SoftwareSource,
      product: string,
      version: string | null,
      row: {
        hosts: string | number;
        ports: string | number;
        scanners: string[] | null;
        first_seen: Date | string;
        last_seen: Date | string;
      }
    ) => {
      if (!product) return;
      const k = key(product, version);
      const hosts = Number(row.hosts);
      const ports = Number(row.ports);
      const firstSeen = new Date(row.first_seen).toISOString();
      const lastSeen = new Date(row.last_seen).toISOString();
      const existing = merged.get(k);
      if (!existing) {
        merged.set(k, {
          product,
          version,
          sources: [source],
          hosts,
          ports,
          scanners: row.scanners ?? [],
          firstSeen,
          lastSeen,
          cveCount: 0,
          maxCvssScore: null,
          hasKev: false,
        });
        return;
      }
      if (!existing.sources.includes(source)) existing.sources.push(source);
      existing.hosts = Math.max(existing.hosts, hosts);
      existing.ports = Math.max(existing.ports, ports);
      existing.scanners = [...new Set([...existing.scanners, ...(row.scanners ?? [])])].sort();
      if (firstSeen < existing.firstSeen) existing.firstSeen = firstSeen;
      if (lastSeen > existing.lastSeen) existing.lastSeen = lastSeen;
    };

    // Services first, so their capitalisation is the one displayed when a
    // web fingerprint reports the same product differently ("nginx" vs
    // "Nginx") - nmap's is the stronger identification of the two.
    for (const row of counts.rows) add("service", row.product, row.version, row);
    for (const row of technologies.rows) {
      const { product, version } = splitTechnology(row.value);
      add("web", product, version, row);
    }
    // Titles are never split for a version: "Welcome to the Apache Tika
    // 2.9.1 Server" is a sentence, not a product and a version, and
    // guessing which part is which is the kind of heuristic that ends up
    // reading as data.
    for (const row of titles.rows) add("title", row.value, null, row);

    // CVEs attach to service rows only - a CPE lives on a port, and
    // neither a technology fingerprint nor a page title carries one. A
    // web-only row therefore reports no CVEs, which is a statement about
    // what is known rather than a claim that none exist; the page says so.
    for (const cve of cves.rows) {
      const row = merged.get(key(cve.product, cve.version));
      if (!row) continue;
      row.cveCount = Number(cve.cve_count);
      row.maxCvssScore = cve.max_cvss;
      row.hasKev = Boolean(cve.has_kev);
    }

    const items = [...merged.values()];

    // Worst first, so a truncated response keeps the rows that matter:
    // confirmed-exploited, then highest CVSS, then most widespread. Same
    // "sort before the cap" discipline as the other fleet-wide finding
    // pages, and the same KEV-outranks-CVSS order the Vulnerabilities
    // page already uses - a confirmed-exploited "high" is more urgent
    // than an unexploited "critical".
    items.sort(
      (a, b) =>
        Number(b.hasKev) - Number(a.hasKev) ||
        (b.maxCvssScore ?? -1) - (a.maxCvssScore ?? -1) ||
        b.hosts - a.hosts ||
        a.product.localeCompare(b.product) ||
        (a.version ?? "").localeCompare(b.version ?? "")
    );

    res.json(limitFindings(items));
  })
);
