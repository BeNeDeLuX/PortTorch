import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { categorisePort, PORT_CATEGORY_ORDER, type PortCategory } from "./portCategories";

export const scanStatsRouter = Router();
scanStatsRouter.use(requireAuth);

// How many slices a "top N" chart keeps before folding the rest into
// "Other" - a donut stops being readable well before the ~200 distinct
// service names a real fleet produces.
const TOP_SLICES = 10;

export interface Slice {
  label: string;
  value: number;
}

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
scanStatsRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  const filterIds = parseScannerAgentIds(req.query.scannerAgentId);
  // Same default as the Dashboard's own list: retired hosts are included
  // unless explicitly hidden, so the fleet never silently looks smaller
  // than it is (see search/routes.ts's hideRetired note).
  const hideRetired = req.query.hideRetired === "1" || req.query.hideRetired === "true";

  // One shared predicate for every query below, so a scanner restriction
  // or the retired filter can't be applied to some numbers on the page
  // and not others.
  const hostWhere = sql`
    ${allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``}
    ${filterIds.length > 0 ? sql`AND h.scanner_agent_id = ANY(${filterIds})` : sql``}
    ${hideRetired ? sql`AND h.retired_at IS NULL` : sql``}
  `;

  const [agents, hostRows, portRows, certRows] = await Promise.all([
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

  const certExpiry: Slice[] = [
    { label: "Expired", value: expired },
    { label: "≤ 30 days", value: expiring30 },
    { label: "31-90 days", value: expiring90 },
    { label: "> 90 days", value: expiryLater },
    { label: "Unknown", value: expiryUnknown },
  ].filter((s) => s.value > 0);

  res.json({
    hideRetired,
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
    certIssuance: [
      { label: "Self-signed", value: selfSigned },
      { label: "CA-issued", value: certRows.rows.length - selfSigned },
    ].filter((s) => s.value > 0),
    certExpiry,
    tlsVersions: topSlices(tlsVersionCounts, 6),
    certKeys: topSlices(keyCounts, 6),
  });
}));
