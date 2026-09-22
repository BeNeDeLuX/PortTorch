import { sql } from "kysely";
import { db } from "../db";

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

  return anomalies;
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
  return (
    `Discovery found ${anomaly.discovered} hosts and only ${anomaly.confirmed} could be confirmed to have an open port. ` +
    `The rest answered the discovery probe but nothing else.`
  );
}
