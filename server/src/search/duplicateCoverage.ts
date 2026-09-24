import { sql } from "kysely";
import { db } from "../db";

// A host's identity is (ip, scanner_agent_id), so two scanners covering
// one range legitimately produce two rows for one machine. Correct
// storage - neither scanner can know it is looking at the same device -
// but every fleet-wide number then counts those machines twice, and
// nothing said so.
//
// The distinction this module exists to draw is *why* an address is
// duplicated, because the two causes call for opposite responses:
//
//   - Both scanners still scan it. A configuration choice: narrow one
//     scanner's target range, or keep the redundancy deliberately.
//   - One scanner's rows are simply old. Nothing is double-scanning at
//     all; leftovers from a scan that ran once and was never repeated sit
//     there until retention takes them, which on a 180-day window is most
//     of a year. Telling that operator to "narrow a target range" is
//     advice about a problem they do not have - measured on a real
//     deployment, where one scanner had touched the range exactly once,
//     three weeks earlier.

// How far behind the freshest holder a row has to be before it reads as a
// leftover rather than a slightly-out-of-step rescan. Deliberately
// measured against the *other holders of that same address* rather than
// against now(): a fortnightly schedule is not stale, it is fortnightly,
// and only the comparison between the holders says which side is actually
// keeping the address current. Display-only heuristic, like Fleet Health's
// own queue and template thresholds.
export const DUPLICATE_STALE_DAYS = 14;

export interface DuplicateHolder {
  scanner: string;
  lastSeen: string;
  // True when this holder is DUPLICATE_STALE_DAYS or more behind the
  // freshest holder of the same address.
  stale: boolean;
}

export interface DuplicateCoverage {
  hostRows: number;
  distinctAddresses: number;
  duplicatedAddresses: number;
  // Of those, how many have at least one holder that has fallen behind.
  staleDuplicates: number;
  duplicates: Array<{ ip: string; holders: DuplicateHolder[] }>;
  truncated: boolean;
  acknowledgement: {
    until: string;
    by: string | null;
    acceptedCount: number | null;
    // Whether it currently suppresses the warning. False once it has
    // expired, or once more addresses are duplicated than were accepted -
    // a growing overlap is news even while the known one is accepted.
    active: boolean;
  } | null;
}

const LIST_LIMIT = 100;

export async function computeDuplicateCoverage(allowedScannerAgentIds: string[] | null): Promise<DuplicateCoverage> {
  let totalsQuery = db.selectFrom("hosts");
  if (allowedScannerAgentIds) totalsQuery = totalsQuery.where("hosts.scanner_agent_id", "in", allowedScannerAgentIds);
  const totals = await totalsQuery
    .select([sql<string>`count(*)`.as("host_rows"), sql<string>`count(distinct hosts.ip)`.as("distinct_addresses")])
    .executeTakeFirstOrThrow();

  // leftJoin, not inner: scanner_agent_id is ON DELETE SET NULL, so a
  // host whose scanner was deleted still occupies an address. An inner
  // join dropped exactly those, which made the list disagree with the
  // count beside it.
  const duplicateBase = () => {
    let q = db
      .selectFrom("hosts")
      .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
      .groupBy("hosts.ip")
      .having(sql<boolean>`count(*) > 1`);
    if (allowedScannerAgentIds) q = q.where("hosts.scanner_agent_id", "in", allowedScannerAgentIds);
    return q;
  };

  const rows = await duplicateBase()
    .select([
      sql<string>`host(hosts.ip)`.as("ip"),
      sql<Array<{ scanner: string; lastSeen: string }>>`json_agg(json_build_object(
        'scanner', coalesce(scanner_agents.name, '(deleted scanner)'),
        'lastSeen', hosts.last_seen_at
      ) order by hosts.last_seen_at desc)`.as("holders"),
    ])
    .orderBy(sql`min(hosts.ip)`)
    .limit(LIST_LIMIT)
    .execute();

  // Counted over every duplicate, not just the listed page: the advice
  // the card gives depends on these two numbers, and basing it on a
  // capped sample would make it wrong exactly when the list is longest.
  //
  // Also counted rather than derived from hostRows - distinctAddresses:
  // that difference is the number of excess *rows*, a different number
  // the moment one address is held by three scanners rather than two.
  const stats = await db
    .selectFrom(
      duplicateBase()
        .select([
          sql<Date>`max(hosts.last_seen_at)`.as("newest"),
          sql<Date>`min(hosts.last_seen_at)`.as("oldest"),
        ])
        .as("dupes")
    )
    .select([
      sql<string>`count(*)`.as("total"),
      sql<string>`count(*) filter (where newest - oldest >= make_interval(days => ${DUPLICATE_STALE_DAYS}))`.as("stale"),
    ])
    .executeTakeFirstOrThrow();

  const duplicatedAddresses = Number(stats.total);

  return {
    hostRows: Number(totals.host_rows),
    distinctAddresses: Number(totals.distinct_addresses),
    duplicatedAddresses,
    staleDuplicates: Number(stats.stale),
    duplicates: rows.map((r) => ({ ip: r.ip, holders: withStaleFlags(r.holders) })),
    truncated: rows.length === LIST_LIMIT,
    acknowledgement: await readAcknowledgement(duplicatedAddresses),
  };
}

// json_agg orders newest-first above, so the first holder is the yardstick.
function withStaleFlags(holders: Array<{ scanner: string; lastSeen: string }>): DuplicateHolder[] {
  if (holders.length === 0) return [];
  const newest = new Date(holders[0].lastSeen).getTime();
  const cutoffMs = DUPLICATE_STALE_DAYS * 24 * 60 * 60 * 1000;
  return holders.map((h) => ({
    scanner: h.scanner,
    lastSeen: new Date(h.lastSeen).toISOString(),
    stale: newest - new Date(h.lastSeen).getTime() >= cutoffMs,
  }));
}

async function readAcknowledgement(currentCount: number): Promise<DuplicateCoverage["acknowledgement"]> {
  const row = await db
    .selectFrom("app_settings")
    .select(["duplicate_coverage_ack_until", "duplicate_coverage_ack_count", "duplicate_coverage_ack_by"])
    .where("id", "=", 1)
    .executeTakeFirst();
  if (!row?.duplicate_coverage_ack_until) return null;

  const until = new Date(row.duplicate_coverage_ack_until);
  const accepted = row.duplicate_coverage_ack_count;
  // Expired, or the overlap grew past what was accepted. A shrinking one
  // stays suppressed - it is moving in the direction the operator wanted.
  const active = until.getTime() > Date.now() && (accepted === null || currentCount <= accepted);

  return {
    until: until.toISOString(),
    by: row.duplicate_coverage_ack_by,
    acceptedCount: accepted,
    active,
  };
}

export async function setDuplicateCoverageAck(until: string, acceptedCount: number, by: string | null): Promise<void> {
  await db
    .updateTable("app_settings")
    .set({
      duplicate_coverage_ack_until: until,
      duplicate_coverage_ack_count: acceptedCount,
      duplicate_coverage_ack_by: by,
    })
    .where("id", "=", 1)
    .execute();
}

export async function clearDuplicateCoverageAck(): Promise<void> {
  await db
    .updateTable("app_settings")
    .set({
      duplicate_coverage_ack_until: null,
      duplicate_coverage_ack_count: null,
      duplicate_coverage_ack_by: null,
    })
    .where("id", "=", 1)
    .execute();
}
