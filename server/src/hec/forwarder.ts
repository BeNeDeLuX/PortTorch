import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings, type HecSettings } from "../settings/appSettings";
import { postToHec } from "./client";
import { caBundle } from "../settings/caCertificates";
import { auditEvent, findingEvent, observationEvent, scanLogEvents, type HecEvent } from "./format";

// Often enough that a SIEM feed is useful for alerting, rarely enough
// that an idle deployment isn't querying two tables every few seconds.
const FORWARD_INTERVAL_MS = 60_000;

// Per tick, per stream. The cap is what keeps the very first run after
// enabling this - which may face months of audit history - from building
// one enormous request; the cursor simply advances and the next tick
// takes the following slice.
const MAX_ROWS_PER_TICK = 500;

// One POST carries at most this many events. A scan job's log can be
// 10 000 lines on its own (the ingest schema's own ceiling), so batching
// by *event* rather than by source row is what bounds the request size.
const MAX_EVENTS_PER_POST = 200;

// A timestamp cursor has to be compared at the precision it is stored
// at. Postgres keeps timestamptz to microseconds; node-postgres hands it
// to JS as a Date, which is milliseconds, so writing the cursor back
// truncates it - and "created_at > cursor" is then still true for the
// very row the cursor was taken from. The stream re-sends everything, on
// every tick, forever.
//
// Truncating both sides to milliseconds in SQL makes the comparison
// exact. It costs the index on these columns, which is irrelevant at the
// row counts involved and is worth strictly less than a cursor that
// works. Found by writing the second-pass assertion the scan-log stream
// never had; the observation stream below is immune by construction,
// since a bigserial has no precision to lose.
const MS = (column: string) => sql<Date>`date_trunc('milliseconds', ${sql.ref(column)})`;

export function startHecForwarder(): void {
  setInterval(() => {
    runHecForward().catch((err) =>
      logger.error({ event: "hec.tick_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, FORWARD_INTERVAL_MS);
}

// Exported so tests can drive one full pass deterministically instead of
// waiting on the interval - same shape as runOperationalAlertChecks and
// runRetentionSweep.
export async function runHecForward(): Promise<{ audit: number; scanLog: number; observations: number; findings: number }> {
  const none = { audit: 0, scanLog: 0, observations: 0, findings: 0 };
  const settings = (await getAppSettings()).hec;
  if (!settings.url || !settings.token) return none;
  if (!settings.auditEnabled && !settings.scanLogEnabled && !settings.observationsEnabled && !settings.findingsEnabled) {
    return none;
  }

  let audit = 0;
  let scanLog = 0;
  let observations = 0;
  let findings = 0;
  if (settings.auditEnabled) audit = await forwardAudit(settings);
  if (settings.scanLogEnabled) scanLog = await forwardScanLogs(settings);
  if (settings.observationsEnabled) observations = await forwardObservations(settings);
  if (settings.findingsEnabled) findings = await forwardFindings(settings);
  return { audit, scanLog, observations, findings };
}

async function state() {
  return db
    .selectFrom("hec_state")
    .select([
      "audit_cursor",
      "scan_log_cursor_at",
      "scan_log_cursor_job_id",
      "observation_cursor",
      "finding_cursor_at",
      "finding_cursor_id",
    ])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
}

async function recordFailure(error: string): Promise<void> {
  await db
    .updateTable("hec_state")
    .set({ last_attempt_at: new Date().toISOString(), last_error: error })
    .where("id", "=", 1)
    .execute();
  logger.error({ event: "hec.forward_failed", error });
}

async function recordSuccess(count: number): Promise<void> {
  const now = new Date().toISOString();
  // bigint, so it round-trips as a string in the driver - incremented in
  // SQL rather than read-modify-written in JS, which would also race two
  // ticks against each other.
  await db
    .updateTable("hec_state")
    .set({
      last_attempt_at: now,
      last_success_at: now,
      last_error: null,
      events_forwarded: sql<string>`events_forwarded + ${count}`,
    })
    .where("id", "=", 1)
    .execute();
}

// Sends in slices, and only advances the cursor for slices the collector
// actually accepted. A failure mid-way leaves the cursor at the last
// acknowledged event, so the next tick resumes there - at worst repeating
// the slice that was in flight when the connection broke, never skipping
// one. At-least-once, deliberately: a SIEM can dedupe a repeat, but it
// cannot recover an event it never received.
async function send(settings: HecSettings, events: HecEvent[]): Promise<boolean> {
  for (let i = 0; i < events.length; i += MAX_EVENTS_PER_POST) {
    const slice = events.slice(i, i + MAX_EVENTS_PER_POST);
    const result = await postToHec(settings, slice, await caBundle());
    if (!result.ok) {
      await recordFailure(result.error ?? "unknown error");
      return false;
    }
  }
  return true;
}

async function forwardAudit(settings: HecSettings): Promise<number> {
  const { audit_cursor } = await state();

  let query = db
    .selectFrom("audit_log")
    .select(["id", "event", "actor", "source_ip", "details", "created_at"])
    .orderBy("id")
    .limit(MAX_ROWS_PER_TICK);
  if (audit_cursor !== null) query = query.where("id", ">", audit_cursor);

  const rows = await query.execute();
  if (rows.length === 0) return 0;

  const events = rows.map((r) => auditEvent(r, settings));
  if (!(await send(settings, events))) return 0;

  await db
    .updateTable("hec_state")
    .set({ audit_cursor: rows[rows.length - 1].id })
    .where("id", "=", 1)
    .execute();
  await recordSuccess(events.length);
  logger.info({ event: "hec.audit_forwarded", events: events.length, through_audit_id: String(rows[rows.length - 1].id) });
  return events.length;
}

async function forwardScanLogs(settings: HecSettings): Promise<number> {
  const { scan_log_cursor_at, scan_log_cursor_job_id } = await state();

  let query = db
    .selectFrom("scan_job_full_log")
    .leftJoin("scan_jobs", "scan_jobs.id", "scan_job_full_log.scan_job_id")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .select([
      "scan_job_full_log.scan_job_id as scan_job_id",
      "scan_job_full_log.logs as logs",
      MS("scan_job_full_log.created_at").as("created_at"),
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scanner_agents.name as scanner_agent_name",
    ])
    .orderBy(MS("scan_job_full_log.created_at"))
    .orderBy("scan_job_full_log.scan_job_id")
    // Deliberately smaller than the audit slice: each row here expands
    // into up to 10 000 events.
    .limit(25);

  // (created_at, scan_job_id) as one ordered key - created_at alone would
  // either skip rows sharing a timestamp or resend them forever.
  //
  // The job id is only a tiebreaker *within* one timestamp, so when it is
  // null there is nothing to tie-break against and the comparison is the
  // plain one. Substituting a placeholder id here is not an option: the
  // column is uuid, and "" is not one.
  if (scan_log_cursor_at !== null) {
    const cursorAt = scan_log_cursor_at;
    const cursorJobId = scan_log_cursor_job_id;
    query = query.where((eb) =>
      cursorJobId === null
        ? eb(MS("scan_job_full_log.created_at"), ">", cursorAt)
        : eb.or([
            eb(MS("scan_job_full_log.created_at"), ">", cursorAt),
            eb.and([
              eb(MS("scan_job_full_log.created_at"), "=", cursorAt),
              eb("scan_job_full_log.scan_job_id", ">", cursorJobId),
            ]),
          ])
    );
  }

  const rows = await query.execute();
  if (rows.length === 0) return 0;

  const events = rows.flatMap((r) =>
    scanLogEvents(r, settings, {
      scanner_agent_name: r.scanner_agent_name,
      target_spec: r.target_spec ?? "",
      port_spec: r.port_spec ?? "",
    })
  );

  // A job whose log is empty still advances the cursor - otherwise it
  // would be re-examined on every tick forever.
  if (events.length > 0 && !(await send(settings, events))) return 0;

  const last = rows[rows.length - 1];
  await db
    .updateTable("hec_state")
    .set({ scan_log_cursor_at: new Date(last.created_at).toISOString(), scan_log_cursor_job_id: last.scan_job_id })
    .where("id", "=", 1)
    .execute();
  if (events.length > 0) {
    await recordSuccess(events.length);
    logger.info({ event: "hec.scan_log_forwarded", events: events.length, scan_jobs: rows.length });
  }
  return events.length;
}

// The scan results themselves. host_port_observations is append-only with
// a bigserial key, so this is the audit stream's shape exactly: everything
// after id N, in id order.
//
// Joined to hosts rather than sending a bare host_id: an event carrying
// only an internal uuid is useless in a SIEM, where the address is what
// every other source keys on.
async function forwardObservations(settings: HecSettings): Promise<number> {
  const { observation_cursor } = await state();

  let query = db
    .selectFrom("host_port_observations")
    .innerJoin("hosts", "hosts.id", "host_port_observations.host_id")
    .leftJoin("scan_jobs", "scan_jobs.id", "host_port_observations.scan_job_id")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .select([
      "host_port_observations.id as id",
      "host_port_observations.host_id as host_id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "host_port_observations.scan_job_id as scan_job_id",
      "host_port_observations.port as port",
      "host_port_observations.protocol as protocol",
      "host_port_observations.state as state",
      "host_port_observations.service_name as service_name",
      "host_port_observations.service_product as service_product",
      "host_port_observations.service_version as service_version",
      "host_port_observations.banner as banner",
      "host_port_observations.observed_at as observed_at",
      "scanner_agents.name as scanner_agent_name",
    ])
    .orderBy("host_port_observations.id")
    .limit(MAX_ROWS_PER_TICK);
  if (observation_cursor !== null) {
    query = query.where("host_port_observations.id", ">", observation_cursor);
  }

  const rows = await query.execute();
  if (rows.length === 0) return 0;

  const events = rows.map((r) => observationEvent(r, settings));
  if (!(await send(settings, events))) return 0;

  await db
    .updateTable("hec_state")
    .set({ observation_cursor: String(rows[rows.length - 1].id) })
    .where("id", "=", 1)
    .execute();
  await recordSuccess(events.length);
  logger.info({
    event: "hec.observations_forwarded",
    events: events.length,
    through_observation_id: String(rows[rows.length - 1].id),
  });
  return events.length;
}

// Web findings. nuclei_findings is keyed by uuid rather than a sequence,
// so the cursor is the same (timestamp, id) pair the scan-log stream
// uses - a timestamp alone would either skip rows sharing one or resend
// them forever. Unlike that one the id is never null, so there is no
// null-tiebreaker branch to carry here.
async function forwardFindings(settings: HecSettings): Promise<number> {
  const { finding_cursor_at, finding_cursor_id } = await state();

  let query = db
    .selectFrom("nuclei_findings")
    .innerJoin("hosts", "hosts.id", "nuclei_findings.host_id")
    .leftJoin("scan_jobs", "scan_jobs.id", "nuclei_findings.scan_job_id")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .select([
      "nuclei_findings.id as id",
      "nuclei_findings.host_id as host_id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "nuclei_findings.scan_job_id as scan_job_id",
      "nuclei_findings.port as port",
      "nuclei_findings.template_id as template_id",
      "nuclei_findings.name as name",
      "nuclei_findings.severity as severity",
      "nuclei_findings.matched_at as matched_at",
      "nuclei_findings.tags as tags",
      MS("nuclei_findings.observed_at").as("observed_at"),
      "scanner_agents.name as scanner_agent_name",
    ])
    .orderBy(MS("nuclei_findings.observed_at"))
    .orderBy("nuclei_findings.id")
    .limit(MAX_ROWS_PER_TICK);

  if (finding_cursor_at !== null) {
    const cursorAt = finding_cursor_at;
    const cursorId = finding_cursor_id;
    query = query.where((eb) =>
      cursorId === null
        ? eb(MS("nuclei_findings.observed_at"), ">", cursorAt)
        : eb.or([
            eb(MS("nuclei_findings.observed_at"), ">", cursorAt),
            eb.and([
              eb(MS("nuclei_findings.observed_at"), "=", cursorAt),
              eb("nuclei_findings.id", ">", cursorId),
            ]),
          ])
    );
  }

  const rows = await query.execute();
  if (rows.length === 0) return 0;

  const events = rows.map((r) => findingEvent(r, settings));
  if (!(await send(settings, events))) return 0;

  const last = rows[rows.length - 1];
  await db
    .updateTable("hec_state")
    .set({
      finding_cursor_at: new Date(last.observed_at).toISOString(),
      finding_cursor_id: last.id,
    })
    .where("id", "=", 1)
    .execute();
  await recordSuccess(events.length);
  logger.info({ event: "hec.findings_forwarded", events: events.length });
  return events.length;
}
