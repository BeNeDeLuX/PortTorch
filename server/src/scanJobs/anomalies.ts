import { sql } from "kysely";
import { db } from "../db";
import { getAppSettings } from "../settings/appSettings";

// Scan-quality checks, run once when a job reaches a terminal status.
//
// The platform recorded what it found and never said how much of it to
// believe. Two artefacts, both measured on a real deployment, are common
// enough on internal networks to be worth naming automatically:
//
//   - One device answering for a whole range. Something intercepting
//     :53 made 261 addresses look like 261 Unbound resolvers, when three
//     existed. nmap fingerprints each address perfectly correctly; the
//     mistake is only visible across the range, which is exactly the view
//     no per-host page has.
//   - Discovery finding far more than enrichment can confirm. A nightly
//     /24 discovered 256 hosts and confirmed 5, every night, for weeks.
//
// Computed from what actually landed in the database rather than from the
// scanner's own tally, same reasoning as the completion counts beside
// them - the one exception being discoveredHosts, which only the scanner
// can know.
//
// Deliberately descriptive, not corrective: nothing here deletes or
// rewrites an observation. An artefact is a statement about how to read
// the data, and the operator is the one who knows whether a range really
// does hold 260 resolvers.

// A single service has to cover this much of the job's hosts before it
// reads as one device answering for the range rather than a genuinely
// uniform estate.
export const DOMINANT_SERVICE_SHARE = 0.8;
// Below this many hosts the share means little - three hosts of which
// two run DNS is 67% and says nothing.
export const DOMINANT_SERVICE_MIN_HOSTS = 20;

// Discovery finding four times what enrichment confirms is the signal.
export const CONFIRMED_SHARE_FLOOR = 0.25;
export const UNCONFIRMED_MIN_DISCOVERED = 20;

// A third artefact, from the scanner's own host metrics: the host ran at
// its limit for most of the scan. masscan is a stateless prober - an
// overloaded host drops replies it never gets to read, and those ports
// simply do not appear - so a scan like that is likely incomplete, and
// nothing in its results says so. "Most of" is half the minute samples
// at or above the admin's CPU or memory alert line, with at least five
// samples so a two-minute scan with one busy minute is not a finding.
export const SATURATED_SHARE = 0.5;
export const SATURATED_MIN_SAMPLES = 5;

export type ScanAnomaly =
  | {
      kind: "dominant_service";
      port: number;
      protocol: string;
      product: string | null;
      serviceName: string | null;
      hosts: number;
      totalHosts: number;
    }
  | {
      kind: "unconfirmed_discovery";
      discovered: number;
      confirmed: number;
    }
  | {
      kind: "host_saturated";
      // Share of the scan's minute samples at or above the alert line.
      share: number;
      samples: number;
      peakCpu: number;
      peakMemPercent: number | null;
    };

export async function detectScanAnomalies(scanJobId: string, discoveredHosts: number | null): Promise<ScanAnomaly[]> {
  const anomalies: ScanAnomaly[] = [];

  const totalRow = await db
    .selectFrom("host_port_observations")
    .select(sql<string>`count(distinct host_id)`.as("count"))
    .where("scan_job_id", "=", scanJobId)
    .where("state", "=", "open")
    .executeTakeFirst();
  const totalHosts = Number(totalRow?.count ?? 0);

  if (totalHosts >= DOMINANT_SERVICE_MIN_HOSTS) {
    // Grouped on the service as well as the port: two different products
    // on the same port across a range is a real estate, one product on
    // every address is the artefact. A null product still groups - an
    // unfingerprinted port answering everywhere is the same finding.
    const rows = await db
      .selectFrom("host_port_observations")
      .select([
        "port",
        "protocol",
        "service_product",
        "service_name",
        sql<string>`count(distinct host_id)`.as("hosts"),
      ])
      .where("scan_job_id", "=", scanJobId)
      .where("state", "=", "open")
      .groupBy(["port", "protocol", "service_product", "service_name"])
      .orderBy(sql`count(distinct host_id)`, "desc")
      .limit(5)
      .execute();

    for (const row of rows) {
      const hosts = Number(row.hosts);
      if (hosts / totalHosts >= DOMINANT_SERVICE_SHARE) {
        anomalies.push({
          kind: "dominant_service",
          port: row.port,
          protocol: row.protocol,
          product: row.service_product,
          serviceName: row.service_name,
          hosts,
          totalHosts,
        });
      }
    }
  }

  // Null discoveredHosts is "this scanner did not report it", not zero -
  // an older scanner must not produce a finding about itself.
  if (discoveredHosts !== null && discoveredHosts >= UNCONFIRMED_MIN_DISCOVERED) {
    if (totalHosts / discoveredHosts < CONFIRMED_SHARE_FLOOR) {
      anomalies.push({ kind: "unconfirmed_discovery", discovered: discoveredHosts, confirmed: totalHosts });
    }
  }

  const saturated = await detectHostSaturation(scanJobId);
  if (saturated) anomalies.push(saturated);

  return anomalies;
}

async function detectHostSaturation(scanJobId: string): Promise<ScanAnomaly | null> {
  const job = await db
    .selectFrom("scan_jobs")
    .select(["scanner_agent_id", "started_at", "finished_at"])
    .where("id", "=", scanJobId)
    .executeTakeFirst();
  if (!job?.scanner_agent_id) return null;
  const { cpuAlertPercent, memAlertPercent } = await getAppSettings();
  const end = job.finished_at ?? new Date();
  const row = await sql<{ samples: string; hot: string; peak_cpu: number | null; peak_mem: number | null }>`
    SELECT count(*) AS samples,
           count(*) FILTER (WHERE cpu_percent >= ${cpuAlertPercent}
                               OR mem_used_bytes::float / nullif(mem_total_bytes, 0) * 100 >= ${memAlertPercent}) AS hot,
           max(cpu_percent) AS peak_cpu,
           max(mem_used_bytes::float / nullif(mem_total_bytes, 0) * 100) AS peak_mem
    FROM scanner_metrics
    WHERE scanner_agent_id = ${job.scanner_agent_id} AND at >= ${job.started_at.toISOString()} AND at <= ${end.toISOString()}
  `.execute(db);
  const r = row.rows[0];
  const samples = Number(r?.samples ?? 0);
  if (samples < SATURATED_MIN_SAMPLES) return null;
  const share = Number(r.hot) / samples;
  if (share < SATURATED_SHARE) return null;
  return {
    kind: "host_saturated",
    share: Math.round(share * 100) / 100,
    samples,
    peakCpu: Math.round(Number(r.peak_cpu ?? 0)),
    peakMemPercent: r.peak_mem === null ? null : Math.round(Number(r.peak_mem)),
  };
}

// One line of plain English per anomaly, so the same wording serves the
// scan history table, the details popup and the log - rather than three
// places each phrasing it their own way and drifting.
export function describeAnomaly(anomaly: ScanAnomaly): string {
  if (anomaly.kind === "dominant_service") {
    const what = anomaly.product ?? anomaly.serviceName ?? "the same service";
    const share = Math.round((anomaly.hosts / anomaly.totalHosts) * 100);
    return (
      `${what} appears on ${anomaly.port}/${anomaly.protocol} of ${anomaly.hosts} of ${anomaly.totalHosts} hosts ` +
      `(${share}%). One device answering for the whole range looks exactly like this.`
    );
  }
  if (anomaly.kind === "host_saturated") {
    return (
      `The scanner's host was at its CPU or memory limit for ${Math.round(anomaly.share * 100)}% of this scan ` +
      `(peak CPU ${anomaly.peakCpu}%). An overloaded host drops replies, so the results may be incomplete - lower the scan rate or run fewer scans at once.`
    );
  }
  return (
    `Discovery found ${anomaly.discovered} hosts and only ${anomaly.confirmed} could be confirmed to have an open port. ` +
    `The rest answered the discovery probe but nothing else.`
  );
}
