import { db } from "./db";
import { logger } from "./logger";
import { nextCronRun } from "./lib/cron";

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

async function tick(): Promise<void> {
  const due = await db
    .selectFrom("scan_schedules")
    .selectAll()
    .where("enabled", "=", true)
    .where("next_run_at", "<=", new Date())
    .execute();

  for (const schedule of due) {
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
