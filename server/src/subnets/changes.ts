import { sql } from "kysely";
import { db } from "../db";
import { ipv4PrefixToCidr, isIPv4, isIPv4Cidr, isIPv6, isIPv6Cidr } from "../lib/net";

// Each list in a comparison is capped, and says so - a /16 that turned
// over completely between two dates should not produce a response the
// page cannot render.
const CHANGES_LIMIT = 1000;
export const DAY_MS = 24 * 60 * 60 * 1000;

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
export function parseNetwork(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (isIPv4Cidr(v) || isIPv4(v) || isIPv6(v) || isIPv6Cidr(v)) return v;
  return ipv4PrefixToCidr(v);
}

export function parseInstant(value: unknown): Date | null {
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
export interface NetworkChangesOptions {
  // Already validated by parseNetwork.
  network: string;
  from: Date;
  to: Date;
  // The session's scanner restriction (null = unrestricted).
  allowed: string[] | null;
  // An additional scanner filter that can only narrow it.
  filterIds: string[];
  hideRetired: boolean;
}

export async function computeNetworkChanges(opts: NetworkChangesOptions) {
  const { network, from, to, allowed, filterIds, hideRetired } = opts;

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
  return {
    network: canonical.rows[0].network,
    from: from.toISOString(),
    to: to.toISOString(),
    hostsBefore: Number(s.hosts_before),
    hostsAfter: Number(s.hosts_after),
    scansInPeriod: Number(s.scans),
    limit: CHANGES_LIMIT,
    ...lists,
  };
}

export type NetworkChanges = Awaited<ReturnType<typeof computeNetworkChanges>>;
