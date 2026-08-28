import { afterEach, afterAll, beforeAll, describe, expect, it } from "vitest";
import { db } from "../../src/db";
import { runSchedulerTick } from "../../src/scheduler";
import { closeDb, createTestAgent, deleteTestAgent, type TestAgent } from "./helpers";

// The behavior that matters isn't "it doesn't run outside the window" -
// it's that an out-of-window run is *deferred* rather than dropped. A
// schedule that quietly skipped a night and waited a full cycle for the
// next one would be worse than having no window at all.
describe("scan schedule run windows", () => {
  let agent: TestAgent;
  const createdScheduleIds: string[] = [];

  beforeAll(async () => {
    agent = await createTestAgent("it-window-agent");
  });

  afterEach(async () => {
    while (createdScheduleIds.length) {
      const id = createdScheduleIds.pop()!;
      await db.deleteFrom("scan_requests").where("target_spec", "=", "10.55.0.0/24").execute();
      await db.deleteFrom("scan_schedules").where("id", "=", id).execute();
    }
  });

  afterAll(async () => {
    await deleteTestAgent(agent.id);
    await closeDb();
  });

  async function createSchedule(window: {
    start: number | null;
    end: number | null;
    days: number[] | null;
    tz: string | null;
  }): Promise<string> {
    const row = await db
      .insertInto("scan_schedules")
      .values({
        scanner_agent_id: agent.id,
        target_spec: "10.55.0.0/24",
        port_spec: "1-1000",
        schedule_type: "interval",
        interval_minutes: 60,
        enabled: true,
        // Already due, so the only thing that can hold it back is the window.
        next_run_at: new Date(Date.now() - 60_000).toISOString(),
        window_start_minute: window.start,
        window_end_minute: window.end,
        window_days: window.days,
        window_timezone: window.tz,
      })
      .returning(["id"])
      .executeTakeFirstOrThrow();
    createdScheduleIds.push(row.id);
    return row.id;
  }

  async function requestCount(): Promise<number> {
    const rows = await db
      .selectFrom("scan_requests")
      .select(["id"])
      .where("target_spec", "=", "10.55.0.0/24")
      .execute();
    return rows.length;
  }

  async function nextRunAt(id: string): Promise<Date> {
    const row = await db
      .selectFrom("scan_schedules")
      .select(["next_run_at"])
      .where("id", "=", id)
      .executeTakeFirstOrThrow();
    return new Date(row.next_run_at);
  }

  // 2026-08-28 is a Friday.
  const at = (iso: string) => new Date(iso);

  it("fires a due schedule with no window, exactly as before windows existed", async () => {
    await createSchedule({ start: null, end: null, days: null, tz: null });
    await runSchedulerTick(at("2026-08-28T13:00:00Z"));
    expect(await requestCount()).toBe(1);
  });

  it("defers rather than drops a run that comes due outside the window", async () => {
    const id = await createSchedule({ start: 22 * 60, end: 6 * 60, days: null, tz: null });
    const before = await nextRunAt(id);

    await runSchedulerTick(at("2026-08-28T13:00:00Z"));
    expect(await requestCount()).toBe(0);
    // The critical assertion: next_run_at is untouched, so the run is
    // still owed. Advancing it here would silently lose the night.
    expect((await nextRunAt(id)).getTime()).toBe(before.getTime());

    // Window opens - the deferred run happens immediately, not an
    // interval later.
    await runSchedulerTick(at("2026-08-28T22:30:00Z"));
    expect(await requestCount()).toBe(1);
    expect((await nextRunAt(id)).getTime()).toBeGreaterThan(before.getTime());
  });

  it("honours a window that crosses midnight on both sides of it", async () => {
    await createSchedule({ start: 22 * 60, end: 6 * 60, days: null, tz: null });
    await runSchedulerTick(at("2026-08-29T03:00:00Z"));
    expect(await requestCount()).toBe(1);
  });

  it("honours a weekday restriction", async () => {
    await createSchedule({ start: null, end: null, days: [1, 2, 3, 4, 5], tz: null });
    await runSchedulerTick(at("2026-08-29T13:00:00Z")); // Saturday
    expect(await requestCount()).toBe(0);
    await runSchedulerTick(at("2026-08-28T13:00:00Z")); // Friday
    expect(await requestCount()).toBe(1);
  });

  it("evaluates the window in the schedule's own timezone", async () => {
    // 22:00-23:00 Berlin is 20:00-21:00 UTC in August (CEST).
    await createSchedule({ start: 22 * 60, end: 23 * 60, days: null, tz: "Europe/Berlin" });
    await runSchedulerTick(at("2026-08-28T22:30:00Z")); // 00:30 Berlin - outside
    expect(await requestCount()).toBe(0);
    await runSchedulerTick(at("2026-08-28T20:30:00Z")); // 22:30 Berlin - inside
    expect(await requestCount()).toBe(1);
  });
});
