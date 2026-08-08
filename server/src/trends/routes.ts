import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

export const trendsRouter = Router();
trendsRouter.use(requireAuth);

const DEFAULT_DAYS = 90;
const MAX_DAYS = 365;

function parseDays(value: unknown): number {
  const n = typeof value === "string" ? parseInt(value, 10) : NaN;
  if (Number.isNaN(n) || n <= 0) return DEFAULT_DAYS;
  return Math.min(n, MAX_DAYS);
}

// Comma-joined, same convention as the Dashboard's own scannerAgentId
// filter (see CLAUDE.md's "Database shape" section) - kept as its own
// independent AND'd condition alongside the session restriction below
// (getAllowedScannerAgentIds), not merged into one array, so a restricted
// session narrowing further with this filter can only ever narrow, never
// widen past what the restriction already allows.
function parseScannerAgentIds(value: unknown): string[] {
  if (typeof value !== "string" || !value.trim()) return [];
  return value.split(",").map((v) => v.trim()).filter(Boolean);
}

interface DailyCountRow {
  date: Date;
  count: string | number;
}

// Fleet-wide time-series view over data that's already historized -
// host_port_observations is append-only (see CLAUDE.md), hosts.first_seen_at
// is set once at insert, scan_jobs.started_at is set once per scan - none
// of this needed a new migration or new scan-side data collection, it's a
// different read over what's already being persisted for the host detail
// timeline/audit log.
//
// "openPorts" is a daily count of distinct (host, port, protocol) seen in
// an 'open' state that day, not a true point-in-time inventory snapshot
// reconstructed for every past day - that would need the same kind of
// "latest scan as-of X" logic digest/routes.ts uses per host, run once per
// day in the range, which is a much heavier query for marginal benefit on
// a trend graph. "seen open that day" is an honest, cheaper proxy: a port
// that's been open for weeks without a rescan won't inflate every day's
// count, only the days it was actually (re)confirmed open.
trendsRouter.get("/", asyncHandler(async (req, res) => {
  const days = parseDays(req.query.days);
  // Start of day (UTC), (days-1) days before today - so the series covers
  // exactly `days` calendar-day buckets ending on today, inclusive. Using
  // a bare `now - days*ms` cutoff here was a real off-by-one: the last
  // bucket it produced landed one day short of today, so today's own
  // activity never showed up in the series at all - caught by this
  // route's own integration test asserting today's bucket exists, not
  // just reasoned about.
  const now = new Date();
  const todayUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const since = new Date(todayUTC.getTime() - (days - 1) * 24 * 60 * 60 * 1000);
  const allowed = getAllowedScannerAgentIds(req);
  const filterIds = parseScannerAgentIds(req.query.scannerAgentId);
  const needsHostJoin = allowed !== null || filterIds.length > 0;

  const [newHostsRows, totalHostsBefore, scanRows, openPortRows, cveRows] = await Promise.all([
    sql<DailyCountRow>`
      SELECT date_trunc('day', first_seen_at)::date AS date, count(*) AS count
      FROM hosts
      WHERE first_seen_at >= ${since.toISOString()}
        ${allowed ? sql`AND scanner_agent_id = ANY(${allowed})` : sql``}
        ${filterIds.length > 0 ? sql`AND scanner_agent_id = ANY(${filterIds})` : sql``}
      GROUP BY 1
      ORDER BY 1
    `.execute(db),

    // Baseline so "total hosts" on the first day of the window isn't
    // wrongly reported as just that day's new hosts - hosts discovered
    // before the window still count toward the running total shown on it.
    db
      .selectFrom("hosts")
      .select(({ fn }) => fn.countAll<number>().as("count"))
      .where("first_seen_at", "<", since)
      .$if(allowed !== null, (qb) => qb.where("scanner_agent_id", "in", allowed!))
      .$if(filterIds.length > 0, (qb) => qb.where("scanner_agent_id", "in", filterIds))
      .executeTakeFirstOrThrow(),

    sql<DailyCountRow>`
      SELECT date_trunc('day', started_at)::date AS date, count(*) AS count
      FROM scan_jobs
      WHERE started_at >= ${since.toISOString()}
        ${allowed ? sql`AND scanner_agent_id = ANY(${allowed})` : sql``}
        ${filterIds.length > 0 ? sql`AND scanner_agent_id = ANY(${filterIds})` : sql``}
      GROUP BY 1
      ORDER BY 1
    `.execute(db),

    sql<DailyCountRow>`
      SELECT date_trunc('day', hpo.observed_at)::date AS date, count(DISTINCT (hpo.host_id, hpo.port, hpo.protocol)) AS count
      FROM host_port_observations hpo
      ${needsHostJoin ? sql`JOIN hosts h ON h.id = hpo.host_id` : sql``}
      WHERE hpo.state = 'open' AND hpo.observed_at >= ${since.toISOString()}
        ${allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``}
        ${filterIds.length > 0 ? sql`AND h.scanner_agent_id = ANY(${filterIds})` : sql``}
      GROUP BY 1
      ORDER BY 1
    `.execute(db),

    // Same "seen open that day" honesty tradeoff as openPorts above, plus
    // the same caveat one layer further: cve_cache itself is a daily
    // snapshot per CPE (see cve/sync.ts), not a historized-per-day record,
    // so this counts distinct (host, port, CVE) combinations that were
    // both open *and* matched a cached CVE on that day - a CVE newly added
    // to NVD for an already-open, unchanged port shows up on the day the
    // sync noticed it, not the day the port was first seen open.
    sql<DailyCountRow>`
      SELECT date_trunc('day', hpo.observed_at)::date AS date, count(DISTINCT (hpo.host_id, hpo.port, cve_elem->>'id')) AS count
      FROM host_port_observations hpo
      JOIN cve_cache cc ON cc.cpe = ANY(hpo.cpes)
      CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
      ${needsHostJoin ? sql`JOIN hosts h ON h.id = hpo.host_id` : sql``}
      WHERE hpo.state = 'open' AND hpo.observed_at >= ${since.toISOString()}
        ${allowed ? sql`AND h.scanner_agent_id = ANY(${allowed})` : sql``}
        ${filterIds.length > 0 ? sql`AND h.scanner_agent_id = ANY(${filterIds})` : sql``}
      GROUP BY 1
      ORDER BY 1
    `.execute(db),
  ]);

  const newHostsByDate = new Map(newHostsRows.rows.map((r) => [r.date.toISOString().slice(0, 10), Number(r.count)]));
  const scansByDate = new Map(scanRows.rows.map((r) => [r.date.toISOString().slice(0, 10), Number(r.count)]));
  const openPortsByDate = new Map(openPortRows.rows.map((r) => [r.date.toISOString().slice(0, 10), Number(r.count)]));
  const cvesByDate = new Map(cveRows.rows.map((r) => [r.date.toISOString().slice(0, 10), Number(r.count)]));

  const series: Array<{ date: string; newHosts: number; totalHosts: number; scans: number; openPorts: number; cveMatches: number }> = [];
  let runningTotal = Number(totalHostsBefore.count);
  for (let i = 0; i < days; i++) {
    const d = new Date(since.getTime() + i * 24 * 60 * 60 * 1000);
    const key = d.toISOString().slice(0, 10);
    const newHosts = newHostsByDate.get(key) ?? 0;
    runningTotal += newHosts;
    series.push({
      date: key,
      newHosts,
      totalHosts: runningTotal,
      scans: scansByDate.get(key) ?? 0,
      openPorts: openPortsByDate.get(key) ?? 0,
      cveMatches: cvesByDate.get(key) ?? 0,
    });
  }

  res.json({ days, since: since.toISOString(), series });
}));
