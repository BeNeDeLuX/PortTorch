import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings, type HecSettings } from "../settings/appSettings";
import { postToHec } from "./client";
import { auditEvent, scanLogEvents, type HecEvent } from "./format";

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
export async function runHecForward(): Promise<{ audit: number; scanLog: number }> {
  const settings = (await getAppSettings()).hec;
  if (!settings.url || !settings.token) return { audit: 0, scanLog: 0 };
  if (!settings.auditEnabled && !settings.scanLogEnabled) return { audit: 0, scanLog: 0 };

  let audit = 0;
  let scanLog = 0;
  if (settings.auditEnabled) audit = await forwardAudit(settings);
  if (settings.scanLogEnabled) scanLog = await forwardScanLogs(settings);
  return { audit, scanLog };
}

async function state() {
  return db
    .selectFrom("hec_state")
    .select(["audit_cursor", "scan_log_cursor_at", "scan_log_cursor_job_id"])
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
    const result = await postToHec(settings, slice);
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
      "scan_job_full_log.created_at as created_at",
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scanner_agents.name as scanner_agent_name",
    ])
    .orderBy("scan_job_full_log.created_at")
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
        ? eb("scan_job_full_log.created_at", ">", cursorAt)
        : eb.or([
            eb("scan_job_full_log.created_at", ">", cursorAt),
            eb.and([
              eb("scan_job_full_log.created_at", "=", cursorAt),
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
