import { db } from "./db";
import { logger } from "./logger";
import { nextCronRun } from "./lib/cron";
import { isWithinScanWindow } from "./lib/scanWindow";

const TICK_INTERVAL_MS = 60_000;

/**
 * Periodically checks for due scan_schedules and creates a scan_requests
 * row for each one, which the responsible scanner then picks up via
 * polling. Runs in the same process as the webserver (sufficient for a
 * single-instance deployment via Docker Compose).
 */
export function startScheduler(): void {
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "scheduler.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, TICK_INTERVAL_MS);
}

// Exported so the integration tests can drive one pass deterministically
// rather than waiting on the 60-second interval - same shape as
// runOperationalAlertChecks and runRetentionSweep. `now` is injectable
// for the same reason: a window test that had to wait for real wall-clock
// time to enter the window couldn't run at all.
export async function runSchedulerTick(now: Date = new Date()): Promise<void> {
  await tick(now);
}

async function tick(injectedNow?: Date): Promise<void> {
  const due = await db
    .selectFrom("scan_schedules")
    .selectAll()
    .where("enabled", "=", true)
    .where("next_run_at", "<=", new Date())
    .execute();

  const now = injectedNow ?? new Date();

  for (const schedule of due) {
    // Outside its allowed window this schedule is *deferred*, not
    // skipped: next_run_at is deliberately left alone, so the run happens
    // the moment the window opens rather than being silently dropped and
    // waiting a whole interval/cron cycle for the next chance. A nightly
    // sweep whose window opens at 22:00 therefore starts at 22:00 even if
    // its cron said 21:00.
    //
    // Nothing is logged per deferral: this loop runs every 60 seconds, so
    // a schedule waiting eight hours for its window would emit ~480
    // identical lines into a stream every line of which is meant to be
    // worth shipping to a SIEM. The dashboard shows the window and marks
    // the schedule as waiting instead (schedules/routes.ts's
    // window_blocked), and the run that eventually happens is logged
    // normally.
    if (
      !isWithinScanWindow(now, {
        startMinute: schedule.window_start_minute,
        endMinute: schedule.window_end_minute,
        days: schedule.window_days,
        timezone: schedule.window_timezone,
      })
    ) {
      continue;
    }

    // A run whose predecessor is still sitting in the queue is *skipped*,
    // not deferred - the opposite of the scan-window case above, and
    // deliberately so. Deferring would leave next_run_at in the past and
    // fire again on the very next tick; queueing anyway is what turns an
    // hourly schedule into 24 requests a day against a scanner that has
    // stopped polling, which then all run back-to-back when it returns.
    // Neither is what "run this hourly" means: the point of an hourly
    // sweep is a fresh picture every hour, and a two-hour-old request
    // waiting to run produces a picture nobody asked for.
    const alreadyQueued = await db
      .selectFrom("scan_requests")
      .select("id")
      .where("schedule_id", "=", schedule.id)
      .where("status", "=", "pending")
      .executeTakeFirst();

    if (alreadyQueued) {
      await db.transaction().execute(async (trx) => {
        // next_run_at still moves forward, so the schedule stays on its
        // own cadence rather than retrying every 60 seconds; last_run_at
        // deliberately does *not*, since nothing ran.
        await trx
          .updateTable("scan_schedules")
          .set({
            next_run_at: nextRunFor(schedule).toISOString(),
            skipped_runs: (schedule.skipped_runs ?? 0) + 1,
            last_skipped_at: new Date().toISOString(),
          })
          .where("id", "=", schedule.id)
          .execute();
      });

      logger.warn({
        event: "schedule.skipped_still_queued",
        schedule_id: schedule.id,
        scanner_agent_id: schedule.scanner_agent_id,
        target_spec: schedule.target_spec,
        pending_request_id: alreadyQueued.id,
        skipped_runs: (schedule.skipped_runs ?? 0) + 1,
      });
      continue;
    }

    await db.transaction().execute(async (trx) => {
      await trx
        .insertInto("scan_requests")
        .values({
          scanner_agent_id: schedule.scanner_agent_id,
          schedule_id: schedule.id,
          host_id: null,
          target_spec: schedule.target_spec,
          port_spec: schedule.port_spec,
          requested_by: "schedule",
          // Copied straight from the schedule's own already-resolved
          // snapshot, not re-resolved live from scan_profiles - a custom
          // profile edited/deleted after this schedule was last saved must
          // not silently change what it fires (see the scan_profiles
          // migration's own comment). Only re-resolved when the schedule
          // itself is explicitly edited (schedules/routes.ts's PATCH).
          nse_profile: schedule.nse_profile,
          nse_scripts: schedule.nse_scripts,
          nse_profile_label: schedule.nse_profile_label,
          nuclei_profile: schedule.nuclei_profile,
          nuclei_tags: schedule.nuclei_tags,
          nuclei_profile_label: schedule.nuclei_profile_label,
          masscan_rate: schedule.masscan_rate,
          // Snapshotted from the schedule, not re-read live - same reason
          // the profile columns above are (see the root CLAUDE.md).
          priority: schedule.priority,
        })
        .execute();

      // A "once" schedule has nothing to reschedule to - it fires exactly
      // once, then disables itself (kept, not deleted, so it stays visible
      // as a record of what ran and when, same as this codebase's general
      // preference for preserving history over deleting rows). Re-enabling
      // it later (schedules/routes.ts's PATCH) is treated as "run this
      // one-off scan again."
      //
      // schedule_type/interval_minutes/cron_expression's mutual presence is
      // enforced by scan_schedules_type_fields_check - the non-null
      // assertions below just reflect that DB-level guarantee.
      if (schedule.schedule_type === "once") {
        await trx
          .updateTable("scan_schedules")
          .set({ last_run_at: new Date().toISOString(), enabled: false })
          .where("id", "=", schedule.id)
          .execute();
      } else {
        await trx
          .updateTable("scan_schedules")
          .set({ last_run_at: new Date().toISOString(), next_run_at: nextRunFor(schedule).toISOString() })
          .where("id", "=", schedule.id)
          .execute();
      }
    });

    logger.info({
      event: "schedule.triggered",
      schedule_id: schedule.id,
      scanner_agent_id: schedule.scanner_agent_id,
      target_spec: schedule.target_spec,
      port_spec: schedule.port_spec,
    });
  }
}

// When this schedule should next come due. Shared by the fired and the
// skipped path so a skipped run cannot end up on a different cadence
// from a normal one.
//
// A 'once' schedule has no next occurrence at all - it disables itself
// after firing. It can still be skipped (re-armed via "Run again" while
// its previous request is somehow still queued), and pushing it one
// interval forward is the least surprising thing to do with a schedule
// type that has no interval: it stays due, and the next tick tries again.
function nextRunFor(schedule: {
  schedule_type: string;
  cron_expression: string | null;
  interval_minutes: number | null;
}): Date {
  if (schedule.schedule_type === "cron") {
    return nextCronRun(schedule.cron_expression!);
  }
  if (schedule.schedule_type === "interval") {
    return new Date(Date.now() + schedule.interval_minutes! * 60_000);
  }
  return new Date(Date.now() + TICK_INTERVAL_MS);
}
