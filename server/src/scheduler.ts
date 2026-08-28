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

    await db.transaction().execute(async (trx) => {
      await trx
        .insertInto("scan_requests")
        .values({
          scanner_agent_id: schedule.scanner_agent_id,
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
        const nextRunAt =
          schedule.schedule_type === "cron"
            ? nextCronRun(schedule.cron_expression!)
            : new Date(Date.now() + schedule.interval_minutes! * 60_000);
        await trx
          .updateTable("scan_schedules")
          .set({ last_run_at: new Date().toISOString(), next_run_at: nextRunAt.toISOString() })
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
