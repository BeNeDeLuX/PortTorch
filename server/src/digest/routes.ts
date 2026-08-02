import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

export const digestRouter = Router();
digestRouter.use(requireAuth);

interface ScanJobPair {
  host_id: string;
  latest_scan_job_id: string;
  latest_observed_at: Date;
  previous_scan_job_id: string | null;
}

const MAX_RANGE_MS = 90 * 24 * 60 * 60 * 1000;
const DEFAULT_RANGE_MS = 24 * 60 * 60 * 1000;

function parseDate(value: unknown, fallback: Date): Date {
  if (typeof value !== "string") return fallback;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

// Fleet-wide "what changed" view: for every host that had at least one
// observation within [from, to], compares its two most recent distinct
// scan runs as of "to" (same newly-open/newly-closed idea as the per-host
// "Changes since last scan" section, just computed across every host
// instead of one at a time). "to" isn't required to be now - a past-dated
// range reconstructs what the digest would have shown at that point in
// time, since host_scan_jobs is bounded by "<= to" rather than always
// comparing against whatever the actual latest scan is today. A host with
// no previous scan run at all (as of "to") is reported as newly
// discovered rather than diffed.
digestRouter.get("/", asyncHandler(async (req, res) => {
  const to = parseDate(req.query.to, new Date());
  let from = parseDate(req.query.from, new Date(to.getTime() - DEFAULT_RANGE_MS));
  if (from >= to) {
    from = new Date(to.getTime() - DEFAULT_RANGE_MS);
  }
  if (to.getTime() - from.getTime() > MAX_RANGE_MS) {
    from = new Date(to.getTime() - MAX_RANGE_MS);
  }

  const candidates = await sql<ScanJobPair>`
    WITH recent_hosts AS (
      SELECT DISTINCT host_id
      FROM host_port_observations
      WHERE observed_at BETWEEN ${from.toISOString()} AND ${to.toISOString()}
    ),
    host_scan_jobs AS (
      SELECT DISTINCT ON (host_id, scan_job_id) host_id, scan_job_id, observed_at
      FROM host_port_observations
      WHERE host_id IN (SELECT host_id FROM recent_hosts) AND observed_at <= ${to.toISOString()}
    ),
    ranked AS (
      SELECT host_id, scan_job_id, observed_at,
             row_number() OVER (PARTITION BY host_id ORDER BY observed_at DESC) AS rn
      FROM host_scan_jobs
    )
    SELECT
      latest.host_id AS host_id,
      latest.scan_job_id AS latest_scan_job_id,
      latest.observed_at AS latest_observed_at,
      previous.scan_job_id AS previous_scan_job_id
    FROM ranked latest
    LEFT JOIN ranked previous ON previous.host_id = latest.host_id AND previous.rn = 2
    WHERE latest.rn = 1
  `.execute(db);

  const allowed = getAllowedScannerAgentIds(req);
  let hostsQuery = db.selectFrom("hosts").select(["id", "ip", "hostname", "first_seen_at"]);
  if (allowed) {
    hostsQuery = hostsQuery.where("scanner_agent_id", "in", allowed);
  }
  const hosts = await hostsQuery.execute();
  const hostsById = new Map(hosts.map((h) => [h.id, h]));

  // Which scanner reported each host's latest-as-of-"to" scan job - one
  // batched query covering every candidate rather than one query per host
  // (host_scan_jobs above already found the right scan_job_id per host,
  // this just resolves it to a scanner name for display). scanner_agent_id
  // can be null if that agent was since deleted (preserved as history, see
  // CLAUDE.md's "Deleting a scanner agent" section) - null name in that case.
  const latestScanJobIds = [...new Set(candidates.rows.map((c) => c.latest_scan_job_id))];
  const scannerByScanJobId = new Map<string, string | null>();
  if (latestScanJobIds.length > 0) {
    const rows = await db
      .selectFrom("scan_jobs")
      .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
      .select(["scan_jobs.id as scan_job_id", "scanner_agents.name as scanner_agent_name"])
      .where("scan_jobs.id", "in", latestScanJobIds)
      .execute();
    for (const r of rows) {
      scannerByScanJobId.set(r.scan_job_id, r.scanner_agent_name);
    }
  }

  const newHosts: Array<{ id: string; ip: string; hostname: string | null; observedAt: string; scannerAgentName: string | null }> = [];
  const changedHosts: Array<{
    id: string;
    ip: string;
    hostname: string | null;
    observedAt: string;
    scannerAgentName: string | null;
    newlyOpen: Array<{ port: number; service_name: string | null }>;
    newlyClosed: Array<{ port: number; service_name: string | null }>;
  }> = [];

  for (const pair of candidates.rows) {
    const host = hostsById.get(pair.host_id);
    if (!host) continue;
    const observedAt = pair.latest_observed_at.toISOString();
    const scannerAgentName = scannerByScanJobId.get(pair.latest_scan_job_id) ?? null;

    if (!pair.previous_scan_job_id) {
      newHosts.push({ id: host.id, ip: host.ip, hostname: host.hostname, observedAt, scannerAgentName });
      continue;
    }

    const rows = await db
      .selectFrom("host_port_observations")
      .select(["scan_job_id", "port", "state", "service_name"])
      .where("host_id", "=", pair.host_id)
      .where("scan_job_id", "in", [pair.latest_scan_job_id, pair.previous_scan_job_id])
      .execute();

    const latestPorts = new Map(rows.filter((r) => r.scan_job_id === pair.latest_scan_job_id).map((r) => [r.port, r]));
    const previousPorts = new Map(
      rows.filter((r) => r.scan_job_id === pair.previous_scan_job_id).map((r) => [r.port, r])
    );

    const newlyOpen: Array<{ port: number; service_name: string | null }> = [];
    const newlyClosed: Array<{ port: number; service_name: string | null }> = [];

    for (const [port, p] of latestPorts) {
      const prev = previousPorts.get(port);
      if (p.state === "open" && prev?.state !== "open") {
        newlyOpen.push({ port, service_name: p.service_name });
      }
    }
    for (const [port, p] of previousPorts) {
      const cur = latestPorts.get(port);
      if (p.state === "open" && cur?.state !== "open") {
        newlyClosed.push({ port, service_name: p.service_name });
      }
    }

    if (newlyOpen.length > 0 || newlyClosed.length > 0) {
      changedHosts.push({ id: host.id, ip: host.ip, hostname: host.hostname, observedAt, scannerAgentName, newlyOpen, newlyClosed });
    }
  }

  res.json({ from: from.toISOString(), to: to.toISOString(), newHosts, changedHosts, generatedAt: new Date().toISOString() });
}));
