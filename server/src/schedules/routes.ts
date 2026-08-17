import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { isValidCronExpression, nextCronRun } from "../lib/cron";
import { ScanProfileNotFoundError, resolveNSEProfile } from "../scanProfiles/resolve";
import { NucleiProfileNotFoundError, resolveNucleiProfile } from "../nucleiProfiles/resolve";

export const schedulesRouter = Router();
schedulesRouter.use(requireAuth);

schedulesRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let query = db
    .selectFrom("scan_schedules")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_schedules.scanner_agent_id")
    .select([
      "scan_schedules.id as id",
      "scan_schedules.scanner_agent_id as scanner_agent_id",
      "scan_schedules.target_spec as target_spec",
      "scan_schedules.port_spec as port_spec",
      "scan_schedules.schedule_type as schedule_type",
      "scan_schedules.interval_minutes as interval_minutes",
      "scan_schedules.cron_expression as cron_expression",
      "scan_schedules.run_at as run_at",
      "scan_schedules.enabled as enabled",
      "scan_schedules.next_run_at as next_run_at",
      "scan_schedules.last_run_at as last_run_at",
      "scan_schedules.created_by as created_by",
      "scan_schedules.created_at as created_at",
      "scan_schedules.nse_profile as nse_profile",
      "scan_schedules.nse_scripts as nse_scripts",
      "scan_schedules.nse_profile_label as nse_profile_label",
      "scan_schedules.nuclei_profile as nuclei_profile",
      "scan_schedules.nuclei_tags as nuclei_tags",
      "scan_schedules.nuclei_profile_label as nuclei_profile_label",
      "scanner_agents.name as scanner_agent_name",
    ]);

  if (allowed) {
    query = query.where("scan_schedules.scanner_agent_id", "in", allowed);
  }

  const schedules = await query.orderBy("scan_schedules.created_at", "desc").execute();
  res.json(schedules);
}));

const nseProfileSelectionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("default") }),
  z.object({ kind: z.literal("all_safe") }),
  z.object({ kind: z.literal("custom"), profileId: z.string().uuid() }),
]);

const nucleiProfileSelectionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("off") }),
  z.object({ kind: z.literal("safe") }),
  z.object({ kind: z.literal("custom"), profileId: z.string().uuid() }),
]);

const baseScheduleFields = {
  scannerAgentId: z.string().uuid(),
  targetSpec: z.string().min(1),
  portSpec: z.string().min(1),
  // Omitted = Default, same as every scan-profile picker elsewhere.
  profile: nseProfileSelectionSchema.optional(),
  // Omitted = Off, same discipline - independent of the NSE profile above.
  nucleiProfile: nucleiProfileSelectionSchema.optional(),
};

const createScheduleSchema = z.discriminatedUnion("scheduleType", [
  z.object({ scheduleType: z.literal("interval"), ...baseScheduleFields, intervalMinutes: z.number().int().min(1) }),
  z.object({ scheduleType: z.literal("cron"), ...baseScheduleFields, cronExpression: z.string().min(1) }),
  // runAt isn't required to be in the future - a past value just means
  // it fires on the very next scheduler tick (within 60s), the same as
  // any other schedule whose next_run_at has already passed. No reason
  // to reject that; it's a reasonable way to say "run this now."
  z.object({ scheduleType: z.literal("once"), ...baseScheduleFields, runAt: z.string().datetime() }),
]);

schedulesRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createScheduleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  if (parsed.data.scheduleType === "cron" && !isValidCronExpression(parsed.data.cronExpression)) {
    res.status(400).json({ error: "invalid cron expression" });
    return;
  }

  const agent = await db
    .selectFrom("scanner_agents")
    .select(["id", "name"])
    .where("id", "=", parsed.data.scannerAgentId)
    .executeTakeFirst();
  if (!agent) {
    res.status(400).json({ error: "unknown scanner agent" });
    return;
  }

  let resolvedProfile;
  try {
    resolvedProfile = await resolveNSEProfile(parsed.data.profile ?? { kind: "default" });
  } catch (err) {
    if (err instanceof ScanProfileNotFoundError) {
      res.status(400).json({ error: err.message });
      return;
    }
    throw err;
  }

  let resolvedNucleiProfile;
  try {
    resolvedNucleiProfile = await resolveNucleiProfile(parsed.data.nucleiProfile ?? { kind: "off" });
  } catch (err) {
    if (err instanceof NucleiProfileNotFoundError) {
      res.status(400).json({ error: err.message });
      return;
    }
    throw err;
  }

  // The interval type's next_run_at can rely on the column default (now())
  // for an immediate first run, but a cron schedule's first run is whatever
  // the expression's own next occurrence actually is - "now" would be
  // wrong for e.g. "daily at 09:00" created at 2pm. A "once" schedule's
  // next_run_at is just whatever runAt the user picked.
  const schedule = await db
    .insertInto("scan_schedules")
    .values({
      scanner_agent_id: parsed.data.scannerAgentId,
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
      schedule_type: parsed.data.scheduleType,
      interval_minutes: parsed.data.scheduleType === "interval" ? parsed.data.intervalMinutes : null,
      cron_expression: parsed.data.scheduleType === "cron" ? parsed.data.cronExpression : null,
      run_at: parsed.data.scheduleType === "once" ? parsed.data.runAt : null,
      ...(parsed.data.scheduleType === "cron"
        ? { next_run_at: nextCronRun(parsed.data.cronExpression).toISOString() }
        : parsed.data.scheduleType === "once"
          ? { next_run_at: parsed.data.runAt }
          : {}),
      nse_profile: resolvedProfile.nseProfile,
      nse_scripts: resolvedProfile.nseScripts,
      nse_profile_label: resolvedProfile.nseProfileLabel,
      nuclei_profile: resolvedNucleiProfile.nucleiProfile,
      nuclei_tags: resolvedNucleiProfile.nucleiTags,
      nuclei_profile_label: resolvedNucleiProfile.nucleiProfileLabel,
      created_by: req.session.username ?? null,
    })
    .returning(["id"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "schedule.created",
    schedule_id: schedule.id,
    scanner_agent_id: parsed.data.scannerAgentId,
    scanner_agent_name: agent.name,
    target_spec: parsed.data.targetSpec,
    port_spec: parsed.data.portSpec,
    schedule_type: parsed.data.scheduleType,
    interval_minutes: parsed.data.scheduleType === "interval" ? parsed.data.intervalMinutes : undefined,
    cron_expression: parsed.data.scheduleType === "cron" ? parsed.data.cronExpression : undefined,
    run_at: parsed.data.scheduleType === "once" ? parsed.data.runAt : undefined,
    created_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("schedule.created", req.session.username, req.ip, {
    schedule_id: schedule.id,
    target_spec: parsed.data.targetSpec,
    scanner_agent_id: parsed.data.scannerAgentId,
    scanner_agent_name: agent.name,
  });

  res.status(201).json(schedule);
}));

const uuidSchema = z.string().uuid();

const updateScheduleSchema = z.object({
  enabled: z.boolean().optional(),
  intervalMinutes: z.number().int().min(1).optional(),
  cronExpression: z.string().min(1).optional(),
  // Scope/ports/scanner and (for a 'once' schedule) its run time - editing
  // an existing schedule rather than only being able to delete and
  // recreate it. Schedule type itself is deliberately not editable here
  // (see the intervalMinutes/cronExpression type-guards below) - matches
  // this route's existing "converting between types isn't supported"
  // stance.
  targetSpec: z.string().min(1).optional(),
  portSpec: z.string().min(1).optional(),
  scannerAgentId: z.string().uuid().optional(),
  runAt: z.string().datetime().optional(),
  // Omitted = leave unchanged, same discipline as every other optional
  // field here.
  profile: nseProfileSelectionSchema.optional(),
  nucleiProfile: nucleiProfileSelectionSchema.optional(),
});

schedulesRouter.patch("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid schedule id" });
    return;
  }
  const parsed = updateScheduleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  if (
    parsed.data.enabled === undefined &&
    parsed.data.intervalMinutes === undefined &&
    parsed.data.cronExpression === undefined &&
    parsed.data.targetSpec === undefined &&
    parsed.data.portSpec === undefined &&
    parsed.data.scannerAgentId === undefined &&
    parsed.data.runAt === undefined &&
    parsed.data.profile === undefined &&
    parsed.data.nucleiProfile === undefined
  ) {
    res.status(400).json({ error: "nothing to update" });
    return;
  }

  const existing = await db
    .selectFrom("scan_schedules")
    .select(["schedule_type", "next_run_at", "interval_minutes", "cron_expression"])
    .where("id", "=", req.params.id)
    .executeTakeFirst();
  if (!existing) {
    res.status(404).json({ error: "schedule not found" });
    return;
  }

  // intervalMinutes/cronExpression/runAt only ever mean something for a
  // schedule's own type - converting an existing schedule from one type to
  // the other isn't supported (delete and recreate instead), so reject
  // whichever field doesn't match rather than silently ignoring it.
  if (parsed.data.intervalMinutes !== undefined && existing.schedule_type !== "interval") {
    res.status(400).json({ error: `this schedule is ${existing.schedule_type}-based - intervalMinutes doesn't apply` });
    return;
  }
  if (parsed.data.cronExpression !== undefined) {
    if (existing.schedule_type !== "cron") {
      res.status(400).json({ error: `this schedule is ${existing.schedule_type}-based - cronExpression doesn't apply` });
      return;
    }
    if (!isValidCronExpression(parsed.data.cronExpression)) {
      res.status(400).json({ error: "invalid cron expression" });
      return;
    }
  }
  if (parsed.data.runAt !== undefined && existing.schedule_type !== "once") {
    res.status(400).json({ error: `this schedule is ${existing.schedule_type}-based - runAt doesn't apply` });
    return;
  }

  let resolvedProfile: Awaited<ReturnType<typeof resolveNSEProfile>> | undefined;
  if (parsed.data.profile !== undefined) {
    try {
      resolvedProfile = await resolveNSEProfile(parsed.data.profile);
    } catch (err) {
      if (err instanceof ScanProfileNotFoundError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }
  }

  let resolvedNucleiProfile: Awaited<ReturnType<typeof resolveNucleiProfile>> | undefined;
  if (parsed.data.nucleiProfile !== undefined) {
    try {
      resolvedNucleiProfile = await resolveNucleiProfile(parsed.data.nucleiProfile);
    } catch (err) {
      if (err instanceof NucleiProfileNotFoundError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }
  }

  let scannerAgentName: string | null = null;
  if (parsed.data.scannerAgentId !== undefined) {
    const agent = await db
      .selectFrom("scanner_agents")
      .select(["id", "name"])
      .where("id", "=", parsed.data.scannerAgentId)
      .executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scanner agent not found" });
      return;
    }
    scannerAgentName = agent.name;
  }

  // Re-enabling a schedule whose next_run_at is stuck in the past (from
  // however long it sat paused) used to leave it there - the scheduler's
  // tick() treats "next_run_at <= now()" as due, so it would still fire
  // on the very next 60s tick, but the dashboard showed a confusing
  // past-dated "next run" in the meantime. Push it out to a fresh
  // next-occurrence instead, same as if the schedule had just fired -
  // computed from the cron expression for a cron schedule, since "now
  // plus interval" only makes sense for the interval type. A "once"
  // schedule has no notion of a "next" occurrence to compute at all - it
  // auto-disables itself the moment it fires (see scheduler.ts) - so
  // re-enabling one here is really "run this exact one-off scan again",
  // and "now" is the only sensible next_run_at for that.
  let nextRunAt: string | undefined;
  if (parsed.data.runAt !== undefined) {
    // A 'once' schedule's next_run_at always mirrors run_at exactly - this
    // is a real overwrite (the user picked a new time), not the
    // isStale-or-changing recompute below, which only applies to
    // interval/cron schedules.
    nextRunAt = parsed.data.runAt;
  } else {
    // Re-enabling a schedule whose next_run_at is stuck in the past (from
    // however long it sat paused) used to leave it there - the scheduler's
    // tick() treats "next_run_at <= now()" as due, so it would still fire
    // on the very next 60s tick, but the dashboard showed a confusing
    // past-dated "next run" in the meantime. Push it out to a fresh
    // next-occurrence instead, same as if the schedule had just fired -
    // computed from the cron expression for a cron schedule, since "now
    // plus interval" only makes sense for the interval type. A "once"
    // schedule has no notion of a "next" occurrence to compute at all - it
    // auto-disables itself the moment it fires (see scheduler.ts) - so
    // re-enabling one here (without also editing runAt) is really "run
    // this exact one-off scan again", and "now" is the only sensible
    // next_run_at for that.
    const changingScheduleValue = parsed.data.intervalMinutes !== undefined || parsed.data.cronExpression !== undefined;
    if (parsed.data.enabled === true || changingScheduleValue) {
      const isStale = existing.next_run_at.getTime() <= Date.now();
      if (isStale || changingScheduleValue) {
        nextRunAt =
          existing.schedule_type === "cron"
            ? nextCronRun(parsed.data.cronExpression ?? existing.cron_expression!).toISOString()
            : existing.schedule_type === "once"
              ? new Date().toISOString()
              : new Date(Date.now() + (parsed.data.intervalMinutes ?? existing.interval_minutes!) * 60_000).toISOString();
      }
    }
  }

  const result = await db
    .updateTable("scan_schedules")
    .set({
      ...(parsed.data.enabled !== undefined ? { enabled: parsed.data.enabled } : {}),
      ...(parsed.data.intervalMinutes !== undefined ? { interval_minutes: parsed.data.intervalMinutes } : {}),
      ...(parsed.data.cronExpression !== undefined ? { cron_expression: parsed.data.cronExpression } : {}),
      ...(parsed.data.targetSpec !== undefined ? { target_spec: parsed.data.targetSpec } : {}),
      ...(parsed.data.portSpec !== undefined ? { port_spec: parsed.data.portSpec } : {}),
      ...(parsed.data.scannerAgentId !== undefined ? { scanner_agent_id: parsed.data.scannerAgentId } : {}),
      ...(parsed.data.runAt !== undefined ? { run_at: parsed.data.runAt } : {}),
      ...(nextRunAt !== undefined ? { next_run_at: nextRunAt } : {}),
      ...(resolvedProfile !== undefined
        ? {
            nse_profile: resolvedProfile.nseProfile,
            nse_scripts: resolvedProfile.nseScripts,
            nse_profile_label: resolvedProfile.nseProfileLabel,
          }
        : {}),
      ...(resolvedNucleiProfile !== undefined
        ? {
            nuclei_profile: resolvedNucleiProfile.nucleiProfile,
            nuclei_tags: resolvedNucleiProfile.nucleiTags,
            nuclei_profile_label: resolvedNucleiProfile.nucleiProfileLabel,
          }
        : {}),
    })
    .where("id", "=", req.params.id)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    res.status(404).json({ error: "schedule not found" });
    return;
  }

  logger.info({
    event: "schedule.updated",
    schedule_id: req.params.id,
    changes: parsed.data,
    scanner_agent_name: scannerAgentName ?? undefined,
    updated_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("schedule.updated", req.session.username, req.ip, {
    schedule_id: req.params.id,
    changes: parsed.data,
    scanner_agent_name: scannerAgentName ?? undefined,
  });

  res.status(204).end();
}));

schedulesRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid schedule id" });
    return;
  }
  const result = await db
    .deleteFrom("scan_schedules")
    .where("id", "=", req.params.id)
    .executeTakeFirst();

  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "schedule not found" });
    return;
  }

  logger.info({
    event: "schedule.deleted",
    schedule_id: req.params.id,
    deleted_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("schedule.deleted", req.session.username, req.ip, { schedule_id: req.params.id });

  res.status(204).end();
}));
