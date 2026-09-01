import { sql } from "kysely";
import { db } from "../db";
import { cidrToRange, coveredFraction, parseTargetSpecRanges, type IPv4Range } from "../lib/ipRange";
import { getAppSettings } from "../settings/appSettings";

export interface NetworkCoverageRow {
  id: string;
  label: string;
  cidr: string;
  scanner_agent_id: string | null;
  scanner_agent_name: string | null;
  created_by: string;
  created_at: Date;
  coverage_alert_sent_at: Date | null;
  address_count: number;
  host_count: number;
  recent_host_count: number;
  last_covered_at: Date | null;
  covered_fraction: number;
  opaque_scan_count: number;
}

// Coverage is derived on read rather than stored, so it can never drift
// from the scan history. Lives here rather than inline in the route
// because the coverage-stale alert (webhooks/operationalAlerts.ts) has to
// reach the identical verdict - two implementations of "is this range
// covered" would eventually disagree, and the one nobody is looking at
// would be the one that's wrong.
//
// allowedScannerAgentIds scopes the whole calculation for a
// scanner-restricted user (null = unrestricted); the alert path passes
// null, since an alert is not sent on anyone's behalf.
export async function computeNetworkCoverage(
  allowedScannerAgentIds: string[] | null
): Promise<{ staleDays: number; networks: NetworkCoverageRow[] }> {
  const settings = await getAppSettings();
  const staleDays = settings.networkCoverageStaleDays;
  const windowStart = new Date(Date.now() - staleDays * 24 * 60 * 60 * 1000);

  let networksQuery = db
    .selectFrom("monitored_networks")
    .leftJoin("scanner_agents", "scanner_agents.id", "monitored_networks.scanner_agent_id")
    .select([
      "monitored_networks.id as id",
      "monitored_networks.label as label",
      sql<string>`monitored_networks.cidr::text`.as("cidr"),
      "monitored_networks.scanner_agent_id as scanner_agent_id",
      "scanner_agents.name as scanner_agent_name",
      "monitored_networks.created_by as created_by",
      "monitored_networks.created_at as created_at",
      "monitored_networks.coverage_alert_sent_at as coverage_alert_sent_at",
    ]);

  // A scanner-restricted user sees the global ranges (which include their
  // scanner) plus any scoped to a scanner they're allowed to see - never
  // one scoped to a scanner they have no access to at all.
  if (allowedScannerAgentIds) {
    networksQuery = networksQuery.where((eb) =>
      eb.or([
        eb("monitored_networks.scanner_agent_id", "is", null),
        eb("monitored_networks.scanner_agent_id", "in", allowedScannerAgentIds),
      ])
    );
  }

  const networks = await networksQuery.orderBy("monitored_networks.label").execute();
  if (networks.length === 0) return { staleDays, networks: [] };

  // Host counts come straight from Postgres's own inet containment
  // (<<= rather than <<, since a /32 tracked range must still contain its
  // one address - << is *strict* containment and would return nothing).
  const hostCounts = await db
    .selectFrom("monitored_networks")
    .leftJoin("hosts", (join) =>
      join.on(sql<boolean>`hosts.ip <<= monitored_networks.cidr`).on((eb) =>
        eb.or([
          eb("monitored_networks.scanner_agent_id", "is", null),
          eb(sql`hosts.scanner_agent_id`, "=", sql`monitored_networks.scanner_agent_id`),
        ])
      )
    )
    .select([
      "monitored_networks.id as id",
      sql<string>`count(hosts.id)`.as("host_count"),
      sql<string>`count(hosts.id) filter (where hosts.last_seen_at >= ${windowStart})`.as("recent_host_count"),
    ])
    .groupBy("monitored_networks.id")
    .execute();
  const countsById = new Map(hostCounts.map((c) => [c.id, c]));

  // Grouping by target_spec first keeps this small: schedules re-run the
  // same handful of specs over and over, so the number of distinct specs
  // is tiny next to the number of jobs.
  let jobsQuery = db
    .selectFrom("scan_jobs")
    .select([
      "target_spec",
      "scanner_agent_id",
      sql<Date>`max(started_at)`.as("last_started_at"),
      sql<Date>`max(started_at) filter (where started_at >= ${windowStart})`.as("last_started_in_window"),
    ])
    .where("status", "=", "completed")
    .groupBy(["target_spec", "scanner_agent_id"]);
  if (allowedScannerAgentIds) {
    jobsQuery = jobsQuery.where("scanner_agent_id", "in", allowedScannerAgentIds);
  }
  const jobs = await jobsQuery.execute();

  const parsedJobs = jobs.map((j) => ({
    scannerAgentId: j.scanner_agent_id,
    lastStartedAt: j.last_started_at,
    inWindow: j.last_started_in_window !== null,
    ranges: parseTargetSpecRanges(j.target_spec),
  }));

  const rows = networks.map((network) => {
    const counts = countsById.get(network.id);
    const range = cidrToRange(network.cidr);

    let lastCoveredAt: Date | null = null;
    let opaqueSpecs = 0;
    const windowRanges: IPv4Range[] = [];

    if (range) {
      for (const job of parsedJobs) {
        if (network.scanner_agent_id && job.scannerAgentId !== network.scanner_agent_id) continue;
        if (job.ranges === null) {
          // A hostname/IPv6 target: it may well have hit this range, but
          // the webserver can't know (the scanner resolves hostnames, see
          // CLAUDE.md's ad-hoc scan section). Counted and surfaced rather
          // than silently treated as "did not cover", so a low coverage
          // figure can be read for what it is.
          opaqueSpecs += 1;
          continue;
        }
        const overlapping = job.ranges.filter((r) => r.start <= range.end && range.start <= r.end);
        if (overlapping.length === 0) continue;
        if (!lastCoveredAt || job.lastStartedAt > lastCoveredAt) lastCoveredAt = job.lastStartedAt;
        if (job.inWindow) windowRanges.push(...overlapping);
      }
    }

    return {
      ...network,
      address_count: range ? range.end - range.start + 1 : 0,
      host_count: Number(counts?.host_count ?? 0),
      recent_host_count: Number(counts?.recent_host_count ?? 0),
      last_covered_at: lastCoveredAt,
      covered_fraction: range ? coveredFraction(range, windowRanges) : 0,
      opaque_scan_count: opaqueSpecs,
    };
  });

  // Least-covered first: the neglected ranges are the reason this exists,
  // the same "worst first" default the certificates list uses for expiry.
  rows.sort((a, b) => a.covered_fraction - b.covered_fraction || a.label.localeCompare(b.label));

  return { staleDays, networks: rows };
}
