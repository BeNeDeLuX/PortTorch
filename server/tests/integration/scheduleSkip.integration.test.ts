import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runSchedulerTick } from "../../src/scheduler";
import {
  closeDb,
  createTestAgent,
  deleteTestAgent,
  type TestAgent,
} from "./helpers";

const TARGET = "240.33.0.0/24";

// An hourly schedule against a scanner that has stopped polling used to
// queue a request every hour forever - a real, observed case, with 20+
// stacked up for one agent. The queue page exists to clean that up after
// the fact; nothing prevented it.
describe("scheduler skips a run whose predecessor is still queued", () => {
  let agent: TestAgent;
  let scheduleId: string;

  beforeAll(async () => {
    agent = await createTestAgent("it-sched-skip");
    const row = await db
      .insertInto("scan_schedules")
      .values({
        scanner_agent_id: agent.id,
        target_spec: TARGET,
        port_spec: "22",
        schedule_type: "interval",
        interval_minutes: 60,
        next_run_at: new Date(Date.now() - 1000).toISOString(),
        enabled: true,
        created_by: "it",
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    scheduleId = row.id;
  });

  afterAll(async () => {
    await db.deleteFrom("scan_requests").where("schedule_id", "=", scheduleId).execute();
    await db.deleteFrom("scan_schedules").where("id", "=", scheduleId).execute();
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function pendingCount(): Promise<number> {
    const rows = await db
      .selectFrom("scan_requests")
      .select("id")
      .where("schedule_id", "=", scheduleId)
      .where("status", "=", "pending")
      .execute();
    return rows.length;
  }

  async function schedule() {
    return db
      .selectFrom("scan_schedules")
      .select(["next_run_at", "last_run_at", "skipped_runs", "last_skipped_at"])
      .where("id", "=", scheduleId)
      .executeTakeFirstOrThrow();
  }

  it("queues the first run and tags it with the schedule", async () => {
    await runSchedulerTick();
    expect(await pendingCount()).toBe(1);
    const s = await schedule();
    expect(s.last_run_at).not.toBeNull();
    expect(s.skipped_runs).toBe(0);
  });

  it("skips the next due run rather than stacking a second request", async () => {
    // Make it due again without waiting an hour, exactly as the real
    // clock would.
    await db
      .updateTable("scan_schedules")
      .set({ next_run_at: new Date(Date.now() - 1000).toISOString() })
      .where("id", "=", scheduleId)
      .execute();
    const before = await schedule();

    await runSchedulerTick();

    expect(await pendingCount()).toBe(1);
    const after = await schedule();
    expect(after.skipped_runs).toBe(1);
    expect(after.last_skipped_at).not.toBeNull();
    // next_run_at moves on, so the schedule keeps its own cadence rather
    // than retrying every 60 seconds...
    expect(new Date(after.next_run_at).getTime()).toBeGreaterThan(Date.now());
    // ...but last_run_at does not, because nothing ran.
    expect(after.last_run_at).toEqual(before.last_run_at);
  });

  it("resumes normally once the queue drains", async () => {
    await db
      .updateTable("scan_requests")
      .set({ status: "cancelled" })
      .where("schedule_id", "=", scheduleId)
      .where("status", "=", "pending")
      .execute();
    expect(await pendingCount()).toBe(0);

    await db
      .updateTable("scan_schedules")
      .set({ next_run_at: new Date(Date.now() - 1000).toISOString() })
      .where("id", "=", scheduleId)
      .execute();
    await runSchedulerTick();

    expect(await pendingCount()).toBe(1);
    // The counter is a record of what happened, not a live state - it
    // keeps counting up rather than resetting, so "this schedule has been
    // missing runs" stays visible after the cause is fixed.
    expect((await schedule()).skipped_runs).toBe(1);
  });

  it("counts a claimed request as no longer blocking", async () => {
    // 'claimed' means a scanner has taken it and is working on it, so the
    // next run is a fresh picture rather than a duplicate of one waiting
    // in line - only 'pending' blocks.
    await db
      .updateTable("scan_requests")
      .set({ status: "claimed" })
      .where("schedule_id", "=", scheduleId)
      .where("status", "=", "pending")
      .execute();
    await db
      .updateTable("scan_schedules")
      .set({ next_run_at: new Date(Date.now() - 1000).toISOString() })
      .where("id", "=", scheduleId)
      .execute();

    await runSchedulerTick();
    expect(await pendingCount()).toBe(1);
    expect((await schedule()).skipped_runs).toBe(1);
  });
});
