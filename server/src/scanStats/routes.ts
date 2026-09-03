import { Router, type Request } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { categorisePort, PORT_CATEGORY_ORDER, type PortCategory } from "./portCategories";
import { computeSecurityStats } from "./security";
import type { Slice } from "./types";

export const scanStatsRouter = Router();
scanStatsRouter.use(requireAuth);

// How many slices a "top N" chart keeps before folding the rest into
// "Other" - a donut stops being readable well before the ~200 distinct
// service names a real fleet produces.
const TOP_SLICES = 10;

// Rows in the "most of X" tables. Same reasoning as TOP_SLICES: long
// enough to act on, short enough to stay a shortlist rather than becoming
// a second copy of the host list.
const TOP_ROWS = 10;


// Same comma-joined convention (and the same "narrow only, never widen"
// reasoning) as trends/routes.ts - see the note there.
function parseScannerAgentIds(value: unknown): string[] {
  if (typeof value !== "string" || !value.trim()) return [];
  return value.split(",").map((v) => v.trim()).filter(Boolean);
}

function topSlices(counts: Map<string, number>, limit = TOP_SLICES): Slice[] {
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const head = sorted.slice(0, limit).map(([label, value]) => ({ label, value }));
  const tail = sorted.slice(limit).reduce((sum, [, value]) => sum + value, 0);
  return tail > 0 ? [...head, { label: "Other", value: tail }] : head;
}

interface PortRow {
  port: number;
  protocol: string;
  service_name: string | null;
  scanner_agent_id: string | null;
  count: string | number;
}

interface CertRow {
  scanner_agent_id: string | null;
  self_signed: boolean;
  not_after: Date | null;
  tls_version: string | null;
  key_algorithm: string | null;
  key_bits: number | null;
}

// Current-state composition of the fleet, the counterpart to the Trends
// page's time series next to it in the Statistics menu: Trends answers
// "how did this change over time", this answers "what is out there right
// now, and how is it distributed".
//
// Everything reads from current_host_ports (the newest observation per
// host+port, see the init migration's view) rather than the append-only
// host_port_observations, so a port that was open six months ago and has
// been closed since counts as closed - unlike Trends' "seen open that
// day" counters, which are deliberately per-day and historical. The two
// therefore will not agree on an "open ports" number, and shouldn't.
// Both routes below take the same three parameters and must scope
// identically - the page shows their numbers side by side, and a filter
// that applied to one but not the other would be worse than no filter.
function scopeFromRequest(req: Request) {
  return {
    allowed: getAllowedScannerAgentIds(req),
    filterIds: parseScannerAgentIds(req.query.scannerAgentId),
    // Same default as the Dashboard's own list: retired hosts are
    // included unless explicitly hidden, so the fleet never silently
    // looks smaller than it is (see search/routes.ts's hideRetired note).
    hideRetired: req.query.hideRetired === "1" || req.query.hideRetired === "true",
  };
}

// How far back the "compared with" figures look. Absent means don't
// compute them at all, and that is the default deliberately: reconstructing
// what was open on a past date means walking the append-only
// host_port_observations rather than the current-state view, which is a
// materially heavier read. Opt-in keeps the ordinary page load cheap.
const COMPARE_DAY_PRESETS = [7, 30, 90];

function parseCompareDays(value: unknown): number | null {
  const n = typeof value === "string" ? parseInt(value, 10) : NaN;
  return COMPARE_DAY_PRESETS.includes(n) ? n : null;
}

// Scans older than this are ignored by the performance figures: a
// scanner's throughput last spring says nothing about whether it is
// keeping up now, and averaging it in mostly hides a recent change.
const PERFORMANCE_WINDOW_DAYS = 30;

scanStatsRouter.get("/", asyncHandler(async (req, res) => {
  const { allowed, filterIds, hideRetired } = scopeFromRequest(req);
  const compareDays = parseCompareDays(req.query.compareDays);

  // One shared predicate for every query below, so a scanner restriction
  // or the retired filter can't be applied to some numbers on the page
  // and not others.
  const hostWhere = sql`
    ${allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``}
    ${filterIds.length > 0 ? sql`AND h.scanner_agent_id = ANY(${filterIds})` : sql``}
    ${hideRetired ? sql`AND h.retired_at IS NULL` : sql``}
  `;

  const [agents, hostRows, portRows, certRows, osRows, deviceRows, tagRows, scanRows, subnetRows, topHostRows] =
    await Promise.all([
    db.selectFrom("scanner_agents").select(["id", "name"]).where("revoked_at", "is", null).execute(),

    // Every host, including ones with no open port at all - those still
    // count toward "hosts", they just contribute nothing to any port
    // chart.
    sql<{ scanner_agent_id: string | null; count: string | number }>`
      SELECT h.scanner_agent_id, count(*) AS count
      FROM hosts h
      WHERE true ${hostWhere}
      GROUP BY 1
    `.execute(db),

    // Grouped in SQL rather than returning a row per open port: distinct
    // (port, protocol, service) combinations are bounded and small, while
    // the raw set is one row per open port in the entire fleet.
    sql<PortRow>`
      SELECT chp.port, chp.protocol, chp.service_name, h.scanner_agent_id, count(*) AS count
      FROM current_host_ports chp
      JOIN hosts h ON h.id = chp.host_id
      WHERE chp.state = 'open' ${hostWhere}
      GROUP BY 1, 2, 3, 4
    `.execute(db),

    // Newest certificate per host+port, the same identity the fleet-wide
    // Certificates page uses - a host that has been rescanned ten times
    // has ten rows for one certificate, and counting those would report
    // "certificates" as "certificate observations".
    sql<CertRow>`
      SELECT DISTINCT ON (tc.host_id, tc.port)
             h.scanner_agent_id, tc.self_signed, tc.not_after, tc.tls_version,
             tc.key_algorithm, tc.key_bits
      FROM tls_certificates tc
      JOIN hosts h ON h.id = tc.host_id
      WHERE true ${hostWhere}
      ORDER BY tc.host_id, tc.port, tc.captured_at DESC
    `.execute(db),

    // os_family/device_type come from nmap's -O fingerprinting, which
    // nmap only performs for real root - a scanner running unprivileged
    // without install.sh's sudo wrapper produces none of it at all (see
    // scanner/CLAUDE.md). Hosts without a classification are therefore
    // counted as their own slice rather than dropped: on such a fleet
    // that slice is the whole circle, which is a true and immediately
    // legible answer, where an empty chart would just look broken.
    sql<{ value: string | null; count: string | number }>`
      SELECT h.os_family AS value, count(*) AS count
      FROM hosts h
      WHERE true ${hostWhere}
      GROUP BY 1
    `.execute(db),

    sql<{ value: string | null; count: string | number }>`
      SELECT h.device_type AS value, count(*) AS count
      FROM hosts h
      WHERE true ${hostWhere}
      GROUP BY 1
    `.execute(db),

    // Tags are the one dimension here that does not partition the fleet:
    // a host carries as many as apply (service auto-tags plus whatever
    // was added by hand), so these counts sum to more than the host
    // count. The page says so rather than letting the percentages imply
    // otherwise.
    sql<{ value: string; count: string | number }>`
      SELECT ht.tag AS value, count(DISTINCT ht.host_id) AS count
      FROM host_tags ht
      JOIN hosts h ON h.id = ht.host_id
      WHERE true ${hostWhere}
      GROUP BY 1
    `.execute(db),

    // Scan performance is about scan_jobs rather than hosts, so it takes
    // the scanner filter but neither the retired filter nor any host
    // join - a scan that found nothing but took 40 minutes is exactly the
    // kind of thing this is meant to surface.
    sql<{
      scanner_agent_id: string | null;
      status: string;
      count: string | number;
      avg_ms: string | number | null;
      median_ms: string | number | null;
      max_ms: string | number | null;
    }>`
      SELECT sj.scanner_agent_id, sj.status, count(*) AS count,
             avg(extract(epoch FROM (sj.finished_at - sj.started_at)) * 1000) AS avg_ms,
             percentile_cont(0.5) WITHIN GROUP (
               ORDER BY extract(epoch FROM (sj.finished_at - sj.started_at)) * 1000
             ) AS median_ms,
             max(extract(epoch FROM (sj.finished_at - sj.started_at)) * 1000) AS max_ms
      FROM scan_jobs sj
      WHERE sj.finished_at IS NOT NULL
        AND sj.started_at >= now() - make_interval(days => ${PERFORMANCE_WINDOW_DAYS})
        ${allowed ? sql`AND sj.scanner_agent_id = ANY(${allowed})` : sql``}
        ${filterIds.length > 0 ? sql`AND sj.scanner_agent_id = ANY(${filterIds})` : sql``}
      GROUP BY 1, 2
    `.execute(db),

    // Top subnets by exposure. The /24 is derived here rather than read
    // from monitored_networks on purpose: this has to say something
    // useful about a fleet where nobody has declared any networks yet,
    // which is most of them until someone opens that page. IPv6 hosts are
    // left out rather than bucketed into a meaningless /24 - the Network
    // Coverage page's own IPv6 gap, not a new one.
    sql<{ subnet: string; hosts: string | number; open_ports: string | number }>`
      SELECT set_masklen(h.ip::cidr, 24)::text AS subnet,
             count(DISTINCT h.id) AS hosts,
             count(*) FILTER (WHERE chp.state = 'open') AS open_ports
      FROM hosts h
      LEFT JOIN current_host_ports chp ON chp.host_id = h.id
      WHERE family(h.ip) = 4 ${hostWhere}
      GROUP BY 1
    `.execute(db),

    sql<{ id: string; ip: string; hostname: string | null; open_ports: string | number }>`
      -- host(), not ip::text: casting an inet to text appends the /32 that
      -- Postgres omits when the value is rendered on its own, so the plain
      -- cast would put "10.0.0.5/32" in front of the operator.
      SELECT h.id, host(h.ip) AS ip, h.hostname, count(*) AS open_ports
      FROM current_host_ports chp
      JOIN hosts h ON h.id = chp.host_id
      WHERE chp.state = 'open' ${hostWhere}
      GROUP BY h.id, h.ip, h.hostname
      ORDER BY count(*) DESC, h.ip
      LIMIT ${TOP_ROWS}
    `.execute(db),
  ]);

  const agentNames = new Map(agents.map((a) => [a.id, a.name]));

  const portCounts = new Map<string, number>();
  const categoryCounts = new Map<PortCategory, number>();
  const protocolCounts = new Map<string, number>();
  const serviceCounts = new Map<string, number>();
  const openPortsByScanner = new Map<string | null, number>();
  let openPorts = 0;

  for (const row of portRows.rows) {
    const count = Number(row.count);
    openPorts += count;
    portCounts.set(`${row.port}/${row.protocol}`, (portCounts.get(`${row.port}/${row.protocol}`) ?? 0) + count);
    const category = categorisePort(row.port, row.protocol);
    categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + count);
    protocolCounts.set(row.protocol.toUpperCase(), (protocolCounts.get(row.protocol.toUpperCase()) ?? 0) + count);
    // A port nmap could not fingerprint is its own slice rather than
    // being dropped: "how much of this fleet is unidentified" is itself
    // worth seeing, and silently omitting those would make the
    // percentages in this chart mean something different from every
    // other chart on the page.
    const service = row.service_name && row.service_name.trim() ? row.service_name.trim() : "unknown";
    serviceCounts.set(service, (serviceCounts.get(service) ?? 0) + count);
    openPortsByScanner.set(row.scanner_agent_id, (openPortsByScanner.get(row.scanner_agent_id) ?? 0) + count);
  }

  const now = Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  let selfSigned = 0;
  let expired = 0;
  let expiring30 = 0;
  let expiring90 = 0;
  let expiryLater = 0;
  let expiryUnknown = 0;
  const tlsVersionCounts = new Map<string, number>();
  const keyCounts = new Map<string, number>();
  const certsByScanner = new Map<string | null, number>();

  for (const cert of certRows.rows) {
    if (cert.self_signed) selfSigned++;
    certsByScanner.set(cert.scanner_agent_id, (certsByScanner.get(cert.scanner_agent_id) ?? 0) + 1);
    if (!cert.not_after) {
      expiryUnknown++;
    } else {
      const remaining = new Date(cert.not_after).getTime() - now;
      if (remaining < 0) expired++;
      else if (remaining <= 30 * DAY) expiring30++;
      else if (remaining <= 90 * DAY) expiring90++;
      else expiryLater++;
    }
    const version = cert.tls_version && cert.tls_version.trim() ? cert.tls_version.trim() : "unknown";
    tlsVersionCounts.set(version, (tlsVersionCounts.get(version) ?? 0) + 1);
    const key = cert.key_algorithm
      ? `${cert.key_algorithm}${cert.key_bits ? ` ${cert.key_bits}` : ""}`
      : "unknown";
    keyCounts.set(key, (keyCounts.get(key) ?? 0) + 1);
  }

  // "Not classified" rather than "unknown": for these two the absence has
  // a specific, actionable cause (the scanner cannot fingerprint without
  // root), unlike a service nmap genuinely could not identify.
  const labelledCounts = (rows: Array<{ value: string | null; count: string | number }>) => {
    const counts = new Map<string, number>();
    for (const row of rows) {
      const label = row.value && row.value.trim() ? row.value.trim() : "Not classified";
      counts.set(label, (counts.get(label) ?? 0) + Number(row.count));
    }
    return counts;
  };
  const osCounts = labelledCounts(osRows.rows);
  const deviceCounts = labelledCounts(deviceRows.rows);
  const tagCounts = new Map<string, number>(tagRows.rows.map((r) => [r.value, Number(r.count)]));

  const hostsByScanner = new Map<string | null, number>(
    hostRows.rows.map((r) => [r.scanner_agent_id, Number(r.count)])
  );
  const hosts = [...hostsByScanner.values()].reduce((a, b) => a + b, 0);

  // Union of the three maps rather than the agent list: a host whose
  // scanner was deleted keeps its data (hosts.scanner_agent_id is ON
  // DELETE SET NULL, see the hosts table), and dropping those rows here
  // would make the per-scanner breakdown add up to less than the totals
  // beside it.
  const scannerKeys = new Set<string | null>([
    ...hostsByScanner.keys(),
    ...openPortsByScanner.keys(),
    ...certsByScanner.keys(),
  ]);
  const perScanner = [...scannerKeys]
    .map((id) => ({
      id,
      name: id === null ? "(deleted scanner)" : agentNames.get(id) ?? "(deleted scanner)",
      hosts: hostsByScanner.get(id) ?? 0,
      openPorts: openPortsByScanner.get(id) ?? 0,
      certificates: certsByScanner.get(id) ?? 0,
    }))
    .sort((a, b) => b.openPorts - a.openPorts || b.hosts - a.hosts || a.name.localeCompare(b.name));

  // Per-scanner scan performance. Statuses are kept apart rather than
  // averaged together: a cancelled scan's duration says how long someone
  // let it run, not how long that work takes, and a failed one is usually
  // fast for the wrong reason - folding either into one average would
  // make a scanner look faster the more often it breaks.
  interface PerfAgg {
    id: string | null;
    name: string;
    scans: number;
    completed: number;
    failed: number;
    cancelled: number;
    avgDurationMs: number | null;
    medianDurationMs: number | null;
    maxDurationMs: number | null;
  }
  const perfByScanner = new Map<string | null, PerfAgg>();
  for (const row of scanRows.rows) {
    const agg = perfByScanner.get(row.scanner_agent_id) ?? {
      id: row.scanner_agent_id,
      name: row.scanner_agent_id === null ? "(deleted scanner)" : agentNames.get(row.scanner_agent_id) ?? "(deleted scanner)",
      scans: 0,
      completed: 0,
      failed: 0,
      cancelled: 0,
      avgDurationMs: null,
      medianDurationMs: null,
      maxDurationMs: null,
    };
    const count = Number(row.count);
    agg.scans += count;
    if (row.status === "completed") {
      agg.completed += count;
      // Durations come from the completed rows only, for the reason above.
      agg.avgDurationMs = row.avg_ms === null ? null : Math.round(Number(row.avg_ms));
      agg.medianDurationMs = row.median_ms === null ? null : Math.round(Number(row.median_ms));
      agg.maxDurationMs = row.max_ms === null ? null : Math.round(Number(row.max_ms));
    } else if (row.status === "failed") {
      agg.failed += count;
    } else if (row.status === "cancelled") {
      agg.cancelled += count;
    }
    perfByScanner.set(row.scanner_agent_id, agg);
  }
  const scanPerformance = [...perfByScanner.values()].sort((a, b) => b.scans - a.scans || a.name.localeCompare(b.name));

  const topHostsByPorts = topHostRows.rows.map((r) => ({
    hostId: r.id,
    ip: r.ip,
    hostname: r.hostname,
    openPorts: Number(r.open_ports),
  }));

  const topSubnets = subnetRows.rows
    .map((r) => ({ subnet: r.subnet, hosts: Number(r.hosts), openPorts: Number(r.open_ports) }))
    .sort((a, b) => b.openPorts - a.openPorts || b.hosts - a.hosts || a.subnet.localeCompare(b.subnet))
    .slice(0, TOP_ROWS);

  const certExpiry: Slice[] = [
    { label: "Expired", value: expired },
    { label: "≤ 30 days", value: expiring30 },
    { label: "31-90 days", value: expiring90 },
    { label: "> 90 days", value: expiryLater },
    { label: "Unknown", value: expiryUnknown },
  ].filter((s) => s.value > 0);

  // Only computed when asked for - see parseCompareDays. "As of" state is
  // reconstructed the same way current_host_ports defines "now" (the
  // newest observation per identity), just with the clock wound back, so
  // the two numbers being compared are the same measurement rather than
  // two different ones.
  //
  // The honest caveat, surfaced in the UI rather than buried here: hosts
  // deleted since (by retention, or by hand) cannot be counted, so the
  // "then" figure is what is still known about that date, not a snapshot
  // taken on it.
  let comparison: {
    days: number;
    since: string;
    hosts: number;
    openPorts: number;
    certificates: number;
  } | null = null;
  if (compareDays !== null) {
    const cutoff = new Date(Date.now() - compareDays * 24 * 60 * 60 * 1000).toISOString();
    const [thenHosts, thenPorts, thenCerts] = await Promise.all([
      sql<{ count: string | number }>`
        SELECT count(*) AS count FROM hosts h
        WHERE h.first_seen_at <= ${cutoff} ${hostWhere}
      `.execute(db),
      sql<{ count: string | number }>`
        SELECT count(*) AS count FROM (
          SELECT DISTINCT ON (hpo.host_id, hpo.port, hpo.protocol) hpo.state
          FROM host_port_observations hpo
          JOIN hosts h ON h.id = hpo.host_id
          WHERE hpo.observed_at <= ${cutoff} ${hostWhere}
          ORDER BY hpo.host_id, hpo.port, hpo.protocol, hpo.observed_at DESC
        ) latest WHERE latest.state = 'open'
      `.execute(db),
      sql<{ count: string | number }>`
        SELECT count(*) AS count FROM (
          SELECT DISTINCT ON (tc.host_id, tc.port) tc.id
          FROM tls_certificates tc
          JOIN hosts h ON h.id = tc.host_id
          WHERE tc.captured_at <= ${cutoff} ${hostWhere}
          ORDER BY tc.host_id, tc.port, tc.captured_at DESC
        ) latest
      `.execute(db),
    ]);
    comparison = {
      days: compareDays,
      since: cutoff,
      hosts: Number(thenHosts.rows[0]?.count ?? 0),
      openPorts: Number(thenPorts.rows[0]?.count ?? 0),
      certificates: Number(thenCerts.rows[0]?.count ?? 0),
    };
  }

  res.json({
    hideRetired,
    comparison,
    totals: {
      hosts,
      openPorts,
      distinctPorts: portCounts.size,
      distinctServices: serviceCounts.size,
      certificates: certRows.rows.length,
      selfSigned,
      expiringSoon: expired + expiring30,
    },
    perScanner,
    topPorts: topSlices(portCounts),
    // Fixed slice order (PORT_CATEGORY_ORDER) instead of by-size, so a
    // category keeps the same color across scanner filters and across
    // days - unlike the top-N charts, this set is closed and small.
    portCategories: PORT_CATEGORY_ORDER.filter((c) => (categoryCounts.get(c) ?? 0) > 0).map((c) => ({
      label: c,
      value: categoryCounts.get(c) ?? 0,
    })),
    protocols: topSlices(protocolCounts),
    services: topSlices(serviceCounts),
    osFamilies: topSlices(osCounts),
    deviceTypes: topSlices(deviceCounts),
    tags: topSlices(tagCounts),
    scanPerformance,
    performanceWindowDays: PERFORMANCE_WINDOW_DAYS,
    topHostsByPorts,
    topSubnets,
    certIssuance: [
      { label: "Self-signed", value: selfSigned },
      { label: "CA-issued", value: certRows.rows.length - selfSigned },
    ].filter((s) => s.value > 0),
    certExpiry,
    tlsVersions: topSlices(tlsVersionCounts, 6),
    certKeys: topSlices(keyCounts, 6),
  });
}));

// Its own route rather than more fields on the one above: this joins
// cve_cache and unnests a jsonb array per open port, by some distance the
// heaviest read in this app, while the composition stats are three
// grouped counts. Split, the page paints its composition charts
// immediately and fills the security ones in when they arrive, instead of
// waiting on the slowest query for all of it.
scanStatsRouter.get("/security", asyncHandler(async (req, res) => {
  const { allowed, filterIds, hideRetired } = scopeFromRequest(req);
  res.json(await computeSecurityStats(allowed, filterIds, hideRetired));
}));
