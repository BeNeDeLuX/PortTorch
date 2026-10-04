import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { computeNetworkChanges, DAY_MS, parseInstant, parseNetwork } from "./changes";
import { cveNotTriaged, cveRuleNotTriaged, NOT_A_LIVE_RISK_STATES } from "../findingTriage/sqlFilters";

export const subnetsRouter = Router();
subnetsRouter.use(requireAuth);

// The IPv4 grouping sizes offered. /24 is the natural unit of an internal
// network; the wider ones are for a fleet spread across enough /24s that
// one row each stops being an overview. IPv6 hosts are always grouped by
// /64, the one prefix length that means "a subnet" there.
export const SUBNET_PREFIXES = [16, 20, 22, 24] as const;
const DEFAULT_PREFIX = 24;
// A malformed id would otherwise reach the uuid[] cast and turn a bad
// query string into a 500.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface SubnetRow {
  subnet: string;
  family: number;
  hosts: string | number;
  open_ports: string | number;
  hosts_with_cves: string | number;
  critical_hosts: string | number;
  kev_hosts: string | number;
  max_cvss: number | null;
  last_seen_at: Date | null;
}

// "Which network is the problem?" had no answer on any page: the host
// list is per host, Scan Stats is fleet-wide, and Network Coverage only
// knows the ranges someone declared. This groups the hosts that actually
// exist by the subnet their address falls in - derived on read, so it can
// never disagree with the host list it links into.
//
// Risk follows the host list's policy exactly - a false positive or a
// fixed finding is not current exposure, an accepted risk still is - and
// takes the fleet-wide triage rules into account too, as every surface
// that quantifies exposure does (see findingTriage/sqlFilters.ts).
//
// Scoped like Scan Stats: the session's scanner restriction always, an
// optional scanner filter that can only narrow it, and retired hosts
// included unless explicitly hidden, so the fleet never silently looks
// smaller than it is.
subnetsRouter.get("/", asyncHandler(async (req, res) => {
  const requested = parseInt(String(req.query.prefix ?? DEFAULT_PREFIX), 10);
  const prefix = (SUBNET_PREFIXES as readonly number[]).includes(requested) ? requested : DEFAULT_PREFIX;
  const allowed = getAllowedScannerAgentIds(req);
  const filterIds =
    typeof req.query.scannerAgentId === "string" && req.query.scannerAgentId.trim()
      ? req.query.scannerAgentId.split(",").map((v) => v.trim()).filter((v) => UUID.test(v))
      : [];
  const hideRetired = req.query.hideRetired === "1" || req.query.hideRetired === "true";

  const conditions = [sql`true`];
  if (allowed) conditions.push(sql`h.scanner_agent_id = ANY(${allowed}::uuid[])`);
  if (filterIds.length > 0) conditions.push(sql`h.scanner_agent_id = ANY(${filterIds}::uuid[])`);
  if (hideRetired) conditions.push(sql`h.retired_at IS NULL`);

  const { rows } = await sql<SubnetRow>`
    WITH scoped AS (
      SELECT h.id, h.last_seen_at,
             network(set_masklen(h.ip, CASE WHEN family(h.ip) = 4 THEN ${prefix}::int ELSE 64 END)) AS subnet
      FROM hosts h
      WHERE ${sql.join(conditions, sql` AND `)}
    ),
    ports AS (
      SELECT chp.host_id, count(*) FILTER (WHERE chp.state = 'open') AS open_ports
      FROM current_host_ports chp
      JOIN scoped s ON s.id = chp.host_id
      GROUP BY chp.host_id
    ),
    risk AS (
      SELECT chp.host_id,
             max((cve_elem->>'cvssScore')::float) AS max_cvss,
             bool_or(kc.cve_id IS NOT NULL) AS has_kev
      FROM current_host_ports chp
      JOIN scoped s ON s.id = chp.host_id
      JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
      CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
      LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
      WHERE chp.state = 'open'
        AND ${cveNotTriaged("chp.host_id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
        AND ${cveRuleNotTriaged("cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
      GROUP BY chp.host_id
    )
    SELECT s.subnet::text AS subnet,
           family(s.subnet) AS family,
           count(*) AS hosts,
           coalesce(sum(p.open_ports), 0) AS open_ports,
           count(r.host_id) AS hosts_with_cves,
           count(*) FILTER (WHERE r.max_cvss >= 9) AS critical_hosts,
           count(*) FILTER (WHERE r.has_kev) AS kev_hosts,
           max(r.max_cvss) AS max_cvss,
           max(s.last_seen_at) AS last_seen_at
    FROM scoped s
    LEFT JOIN ports p ON p.host_id = s.id
    LEFT JOIN risk r ON r.host_id = s.id
    GROUP BY s.subnet
    ORDER BY s.subnet
  `.execute(db);

  // Every count() here is a bigint, which node-postgres hands back as a
  // string - converted before it leaves, or the frontend's sums and
  // comparisons silently concatenate (a trap this codebase has hit
  // repeatedly; see server/CLAUDE.md's Scan History notes).
  res.json({
    prefix,
    subnets: rows.map((r) => ({
      subnet: r.subnet,
      family: Number(r.family),
      hosts: Number(r.hosts),
      openPorts: Number(r.open_ports),
      hostsWithCves: Number(r.hosts_with_cves),
      criticalHosts: Number(r.critical_hosts),
      kevHosts: Number(r.kev_hosts),
      maxCvss: r.max_cvss === null ? null : Number(r.max_cvss),
      lastSeenAt: r.last_seen_at,
    })),
  });
}));

// What changed in one network between two moments - see changes.ts.
subnetsRouter.get("/changes", asyncHandler(async (req, res) => {
  const network = parseNetwork(String(req.query.network ?? ""));
  if (!network) {
    res.status(400).json({ error: "network must be a CIDR, an address, or a partial IPv4 address such as 10.46" });
    return;
  }
  const to = req.query.to === undefined ? new Date() : parseInstant(req.query.to);
  const from = req.query.from === undefined && to ? new Date(to.getTime() - 7 * DAY_MS) : parseInstant(req.query.from);
  if (!from || !to) {
    res.status(400).json({ error: "from and to must be timestamps" });
    return;
  }
  if (from >= to) {
    res.status(400).json({ error: "from must be before to" });
    return;
  }
  const filterIds =
    typeof req.query.scannerAgentId === "string" && req.query.scannerAgentId.trim()
      ? req.query.scannerAgentId.split(",").map((v) => v.trim()).filter((v) => UUID.test(v))
      : [];
  const hideRetired = req.query.hideRetired === "1" || req.query.hideRetired === "true";
  res.json(
    await computeNetworkChanges({ network, from, to, allowed: getAllowedScannerAgentIds(req), filterIds, hideRetired })
  );
}));
