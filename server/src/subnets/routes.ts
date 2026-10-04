import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { ipv4PrefixToCidr, isIPv4, isIPv4Cidr, isIPv6, isIPv6Cidr } from "../lib/net";
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

// Each list in a comparison is capped, and says so - a /16 that turned
// over completely between two dates should not produce a response the
// page cannot render.
const CHANGES_LIMIT = 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

interface HostChangeRow {
  host_id: string;
  ip: string;
  hostname: string | null;
  scanner_agent_name: string | null;
  first_seen_at: Date;
  last_seen_at: Date | null;
  open_ports: string | null;
}

interface PortChangeRow {
  host_id: string;
  ip: string;
  hostname: string | null;
  port: number;
  protocol: string;
  service_name: string | null;
  observed_at: Date;
}

// Accepts what someone types to name a network: a CIDR, a single address,
// or a partial IPv4 address read as the block it names ("10.46" is
// 10.46.0.0/16) - the same rule as the host list's ip: search. Returns
// what Postgres should cast, or null.
function parseNetwork(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (isIPv4Cidr(v) || isIPv4(v) || isIPv6(v) || isIPv6Cidr(v)) return v;
  return ipv4PrefixToCidr(v);
}

function parseInstant(value: unknown): Date | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

// What changed in one network between two moments: hosts first found in
// between, hosts known before that no scan reported in between, and ports
// that opened or closed on hosts that were already there.
//
// "State at a moment" is reconstructed exactly the way current_host_ports
// defines "now" - the newest observation per host+port+protocol, with the
// clock wound back - so the comparison measures the same thing the rest of
// the dashboard shows. Two consequences, both stated in the UI rather than
// hidden: a port only counts as closed once a scan recorded it closed
// (masscan never reports one, see the port.closed inference), and a host
// "not seen" in the window may be gone or may simply not have been
// scanned - which is why the response says how many scans touched the
// network in between.
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

  const allowed = getAllowedScannerAgentIds(req);
  const filterIds =
    typeof req.query.scannerAgentId === "string" && req.query.scannerAgentId.trim()
      ? req.query.scannerAgentId.split(",").map((v) => v.trim()).filter((v) => UUID.test(v))
      : [];
  const hideRetired = req.query.hideRetired === "1" || req.query.hideRetired === "true";

  const conditions = [sql`h.ip <<= network(${network}::inet)`];
  if (allowed) conditions.push(sql`h.scanner_agent_id = ANY(${allowed}::uuid[])`);
  if (filterIds.length > 0) conditions.push(sql`h.scanner_agent_id = ANY(${filterIds}::uuid[])`);
  if (hideRetired) conditions.push(sql`h.retired_at IS NULL`);
  const scoped = sql`
    SELECT h.id, host(h.ip) AS ip, h.hostname, h.first_seen_at, h.last_seen_at, sa.name AS scanner_agent_name
    FROM hosts h
    LEFT JOIN scanner_agents sa ON sa.id = h.scanner_agent_id
    WHERE ${sql.join(conditions, sql` AND `)}
  `;
  const stateAt = (at: Date) => sql`
    SELECT DISTINCT ON (o.host_id, o.port, o.protocol)
           o.host_id, o.port, o.protocol, o.state, o.service_name, o.observed_at
    FROM host_port_observations o
    JOIN scoped s ON s.id = o.host_id
    WHERE o.observed_at <= ${at.toISOString()}
    ORDER BY o.host_id, o.port, o.protocol, o.observed_at DESC
  `;

  const [canonical, summary, newHosts, unseenHosts, opened, closed] = await Promise.all([
    sql<{ network: string }>`SELECT network(${network}::inet)::text AS network`.execute(db),
    sql<{ hosts_before: string; hosts_after: string; scans: string }>`
      WITH scoped AS (${scoped})
      SELECT
        (SELECT count(*) FROM scoped WHERE first_seen_at <= ${from.toISOString()}) AS hosts_before,
        (SELECT count(*) FROM scoped WHERE first_seen_at <= ${to.toISOString()}) AS hosts_after,
        (SELECT count(DISTINCT o.scan_job_id) FROM host_port_observations o JOIN scoped s ON s.id = o.host_id
          WHERE o.observed_at > ${from.toISOString()} AND o.observed_at <= ${to.toISOString()}) AS scans
    `.execute(db),
    sql<HostChangeRow>`
      WITH scoped AS (${scoped}), after AS (${stateAt(to)})
      SELECT s.id AS host_id, s.ip, s.hostname, s.scanner_agent_name, s.first_seen_at, s.last_seen_at,
             (SELECT string_agg(a.port || '/' || a.protocol, ', ' ORDER BY a.port)
                FROM after a WHERE a.host_id = s.id AND a.state = 'open') AS open_ports
      FROM scoped s
      WHERE s.first_seen_at > ${from.toISOString()} AND s.first_seen_at <= ${to.toISOString()}
      ORDER BY s.first_seen_at DESC
      LIMIT ${CHANGES_LIMIT + 1}
    `.execute(db),
    sql<HostChangeRow>`
      WITH scoped AS (${scoped}), before AS (${stateAt(from)})
      SELECT s.id AS host_id, s.ip, s.hostname, s.scanner_agent_name, s.first_seen_at,
             (SELECT max(o.observed_at) FROM host_port_observations o
                WHERE o.host_id = s.id AND o.observed_at <= ${to.toISOString()}) AS last_seen_at,
             (SELECT string_agg(b.port || '/' || b.protocol, ', ' ORDER BY b.port)
                FROM before b WHERE b.host_id = s.id AND b.state = 'open') AS open_ports
      FROM scoped s
      WHERE s.first_seen_at <= ${from.toISOString()}
        AND NOT EXISTS (
          SELECT 1 FROM host_port_observations o
          WHERE o.host_id = s.id AND o.observed_at > ${from.toISOString()} AND o.observed_at <= ${to.toISOString()}
        )
      ORDER BY s.ip
      LIMIT ${CHANGES_LIMIT + 1}
    `.execute(db),
    sql<PortChangeRow>`
      WITH scoped AS (${scoped}), before AS (${stateAt(from)}), after AS (${stateAt(to)})
      SELECT s.id AS host_id, s.ip, s.hostname, a.port, a.protocol, a.service_name, a.observed_at
      FROM after a
      JOIN scoped s ON s.id = a.host_id
      LEFT JOIN before b ON b.host_id = a.host_id AND b.port = a.port AND b.protocol = a.protocol
      WHERE a.state = 'open'
        AND (b.state IS NULL OR b.state <> 'open')
        AND s.first_seen_at <= ${from.toISOString()}
      ORDER BY s.ip, a.port
      LIMIT ${CHANGES_LIMIT + 1}
    `.execute(db),
    sql<PortChangeRow>`
      WITH scoped AS (${scoped}), before AS (${stateAt(from)}), after AS (${stateAt(to)})
      SELECT s.id AS host_id, s.ip, s.hostname, b.port, b.protocol, b.service_name, a.observed_at
      FROM before b
      JOIN scoped s ON s.id = b.host_id
      JOIN after a ON a.host_id = b.host_id AND a.port = b.port AND a.protocol = b.protocol
      WHERE b.state = 'open' AND a.state <> 'open'
      ORDER BY s.ip, b.port
      LIMIT ${CHANGES_LIMIT + 1}
    `.execute(db),
  ]);

  const capped = <T>(rows: T[]) => ({ items: rows.slice(0, CHANGES_LIMIT), truncated: rows.length > CHANGES_LIMIT });
  const hostOut = (r: HostChangeRow) => ({
    hostId: r.host_id,
    ip: r.ip,
    hostname: r.hostname,
    scannerAgentName: r.scanner_agent_name,
    firstSeenAt: r.first_seen_at,
    lastSeenAt: r.last_seen_at,
    openPorts: r.open_ports ? r.open_ports.split(", ") : [],
  });
  const portOut = (r: PortChangeRow) => ({
    hostId: r.host_id,
    ip: r.ip,
    hostname: r.hostname,
    port: Number(r.port),
    protocol: r.protocol,
    serviceName: r.service_name,
    observedAt: r.observed_at,
  });
  const s = summary.rows[0];
  const lists = {
    newHosts: capped(newHosts.rows.map(hostOut)),
    unseenHosts: capped(unseenHosts.rows.map(hostOut)),
    openedPorts: capped(opened.rows.map(portOut)),
    closedPorts: capped(closed.rows.map(portOut)),
  };
  res.json({
    network: canonical.rows[0].network,
    from: from.toISOString(),
    to: to.toISOString(),
    hostsBefore: Number(s.hosts_before),
    hostsAfter: Number(s.hosts_after),
    scansInPeriod: Number(s.scans),
    limit: CHANGES_LIMIT,
    ...lists,
  });
}));
