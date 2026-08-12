import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, Me, ScannerAgent, Schedule } from "../api";
import { IconEdit, IconPause, IconPlay, IconPlus, IconSave, IconTrash, IconX } from "../components/icons";
import PageHeader from "../components/PageHeader";
import ScannerMultiSelect from "../components/ScannerMultiSelect";
import { formatDateTime } from "../lib/formatDate";
import {
  resolveTimezone,
  shiftWeekday,
  utcHourMinuteToZonedTime,
  utcIsoToZonedDateTimeLocal,
  zonedDateTimeToUtcIso,
  zonedTimeToUtcHourMinute,
} from "../lib/zonedTime";

type SortKey = "target_spec" | "port_spec" | "schedule" | "scanner_agent_name" | "next_run_at" | "last_run_at";
type SortDirection = "asc" | "desc";

const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const DEFAULT_WEEKDAYS = new Set([1, 2, 3, 4, 5]); // Mon-Fri

// A fired "once" schedule (schedule_type='once', auto-disabled by
// scheduler.ts the moment it fires) is its own status, distinct from a
// merely-paused interval/cron schedule - grouping by this (rather than
// showing it as a column, mirroring how ScannerAgents.tsx groups by
// Scanning/Idle/Revoked instead of a redundant status column) makes the
// list scannable at a glance without hunting through a flat table.
type ScheduleStatus = "active" | "done" | "paused";

function scheduleStatus(s: Schedule): ScheduleStatus {
  if (s.schedule_type === "once" && !s.enabled && s.last_run_at) return "done";
  return s.enabled ? "active" : "paused";
}

function scheduleSortValue(s: Schedule): string {
  if (s.schedule_type === "interval") return `${s.interval_minutes} min`;
  if (s.schedule_type === "once") return s.run_at ?? "";
  return s.cron_expression ?? "";
}

function compareSchedules(a: Schedule, b: Schedule, key: SortKey, direction: SortDirection): number {
  const sign = direction === "asc" ? 1 : -1;
  switch (key) {
    case "target_spec":
      return sign * a.target_spec.localeCompare(b.target_spec);
    case "port_spec":
      return sign * a.port_spec.localeCompare(b.port_spec);
    case "schedule":
      return sign * scheduleSortValue(a).localeCompare(scheduleSortValue(b));
    case "scanner_agent_name":
      return sign * (a.scanner_agent_name ?? "").localeCompare(b.scanner_agent_name ?? "");
    case "next_run_at":
      return sign * (new Date(a.next_run_at).getTime() - new Date(b.next_run_at).getTime());
    case "last_run_at": {
      const at = a.last_run_at ? new Date(a.last_run_at).getTime() : -Infinity;
      const bt = b.last_run_at ? new Date(b.last_run_at).getTime() : -Infinity;
      return sign * (at - bt);
    }
    default:
      return 0;
  }
}

// Builds a 5-field, UTC cron expression from the friendly picker state
// below - the picker itself works in the user's preferred timezone (or
// the browser's, if unset), so the picked "HH:MM" is converted to its
// current UTC equivalent first (zonedTimeToUtcHourMinute). That
// conversion can shift the calendar day by ±1 (e.g. "Monday 00:30
// Berlin" in winter is "Sunday 23:30 UTC"), so "days"/"monthly" also
// shift their weekday selection by the same amount, or the schedule
// would fire on the wrong day-of-week in UTC terms. "monthly" uses
// cron-parser's Quartz-style "#"/"L" weekday-of-month extension (e.g.
// "0 9 * * 0#1" = first Sunday, "0 9 * * 0L" = last Sunday) - a plain
// day-of-month + day-of-week combination can't express this, since
// POSIX cron ORs those two fields together instead of ANDing them when
// both are restricted.
function buildCronExpression(
  repeatMode: "daily" | "days" | "monthly",
  time: string,
  selectedDays: Set<number>,
  monthlyOccurrence: string,
  monthlyWeekday: number,
  timezone: string
): string {
  const { hour, minute, dayShift } = zonedTimeToUtcHourMinute(time, timezone);
  if (repeatMode === "daily") {
    return `${minute} ${hour} * * *`;
  }
  if (repeatMode === "days") {
    const days = [...selectedDays].map((d) => shiftWeekday(d, dayShift)).sort((a, b) => a - b);
    return `${minute} ${hour} * * ${days.length ? days.join(",") : "*"}`;
  }
  const occurrence = monthlyOccurrence === "L" ? "L" : `#${monthlyOccurrence}`;
  return `${minute} ${hour} * * ${shiftWeekday(monthlyWeekday, dayShift)}${occurrence}`;
}

interface ParsedCron {
  hour: number;
  minute: number;
  repeatMode: "daily" | "days" | "monthly";
  days: number[] | null;
  monthlyOccurrence: string | null;
  monthlyWeekday: number | null;
}

// Inverse of buildCronExpression, for pre-filling the edit form's friendly
// builder from a stored (UTC) cron expression - returns null for anything
// that isn't exactly one of this builder's own producible shapes (e.g. a
// schedule created via the raw/advanced escape hatch with a real
// day-of-month or month field, or a day-of-week range/step syntax the
// builder itself never generates). The edit form falls back to opening in
// advanced/raw mode with the exact stored string in that case, rather than
// risking silently misrepresenting an expression it can't losslessly
// reconstruct into hour/minute/days.
function parseCronForBuilder(expr: string): ParsedCron | null {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const [minuteStr, hourStr, dom, month, dow] = parts;
  if (dom !== "*" || month !== "*") return null;

  const minute = Number(minuteStr);
  const hour = Number(hourStr);
  if (!Number.isInteger(minute) || !Number.isInteger(hour) || minute < 0 || minute > 59 || hour < 0 || hour > 23) {
    return null;
  }

  if (dow === "*") {
    return { hour, minute, repeatMode: "daily", days: null, monthlyOccurrence: null, monthlyWeekday: null };
  }

  const monthlyMatch = /^([0-6])(?:#([1-4])|(L))$/.exec(dow);
  if (monthlyMatch) {
    const [, weekdayStr, occurrenceDigit, occurrenceLast] = monthlyMatch;
    return {
      hour,
      minute,
      repeatMode: "monthly",
      days: null,
      monthlyOccurrence: occurrenceLast ? "L" : occurrenceDigit,
      monthlyWeekday: Number(weekdayStr),
    };
  }

  if (/^[0-6](,[0-6])*$/.test(dow)) {
    return { hour, minute, repeatMode: "days", days: dow.split(",").map(Number), monthlyOccurrence: null, monthlyWeekday: null };
  }

  return null;
}

export default function Schedules({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === "admin";
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [scannerFilterIds, setScannerFilterIds] = useState<string[]>([]);

  const [scannerAgentId, setScannerAgentId] = useState("");
  const [targetSpec, setTargetSpec] = useState("");
  const [portSpec, setPortSpec] = useState("");
  const [scheduleType, setScheduleType] = useState<"interval" | "cron" | "once">("interval");
  const [intervalMinutes, setIntervalMinutes] = useState(60);
  const [runAt, setRunAt] = useState("");

  const [repeatMode, setRepeatMode] = useState<"daily" | "days" | "monthly">("daily");
  const [time, setTime] = useState("09:00");
  const [selectedDays, setSelectedDays] = useState<Set<number>>(new Set(DEFAULT_WEEKDAYS));
  const [monthlyOccurrence, setMonthlyOccurrence] = useState("1");
  const [monthlyWeekday, setMonthlyWeekday] = useState(0);
  const [advancedCron, setAdvancedCron] = useState(false);
  const [rawCronExpression, setRawCronExpression] = useState("");

  const [sortKey, setSortKey] = useState<SortKey>("next_run_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");

  // Non-null while editing an existing schedule (via the Edit button below)
  // rather than creating a new one - the same form/state above is reused
  // for both, just relabeled and pointed at api.updateSchedule instead of
  // api.createSchedule. Schedule type itself is never editable (see
  // handleEdit/the JSX below) - delete and recreate to change it.
  const [editingId, setEditingId] = useState<string | null>(null);

  // The "Run at"/"Time" pickers below work in this zone (the account
  // preference from Account settings, falling back to the browser's own
  // local zone if unset) rather than raw UTC - see lib/zonedTime.ts.
  const timezone = resolveTimezone(me.preferences.timezone);

  const generatedCron = useMemo(
    () => buildCronExpression(repeatMode, time, selectedDays, monthlyOccurrence, monthlyWeekday, timezone),
    [repeatMode, time, selectedDays, monthlyOccurrence, monthlyWeekday, timezone]
  );

  function setSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDirection("asc");
    }
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return "";
    return sortDirection === "asc" ? " ▲" : " ▼";
  }

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [scheduleList, agentList] = await Promise.all([api.schedules(), api.agents()]);
      setSchedules(scheduleList);
      const activeAgents = agentList.filter((a) => !a.revoked_at);
      setAgents(activeAgents);
      if (activeAgents.length > 0 && !scannerAgentId) {
        setScannerAgentId(activeAgents[0].id);
      }
    } finally {
      setLoading(false);
    }
  }

  function toggleDay(day: number) {
    setSelectedDays((prev) => {
      const next = new Set(prev);
      if (next.has(day)) next.delete(day);
      else next.add(day);
      return next;
    });
  }

  function resetForm() {
    setEditingId(null);
    setTargetSpec("");
    setPortSpec("");
    setRunAt("");
    setScheduleType("interval");
    setIntervalMinutes(60);
    setRepeatMode("daily");
    setTime("09:00");
    setSelectedDays(new Set(DEFAULT_WEEKDAYS));
    setMonthlyOccurrence("1");
    setMonthlyWeekday(0);
    setAdvancedCron(false);
    setRawCronExpression("");
  }

  // Populates the form (shared with create, above) from an existing
  // schedule and switches it into edit mode - scheduleType itself is set
  // just to pick the right fields to show, but stays fixed while editing
  // (see the disabled <select> in the JSX below). The "cron" branch tries
  // to reconstruct the friendly builder's fields from the stored
  // expression; if that expression isn't one of the builder's own
  // producible shapes (e.g. created via the raw escape hatch, or edited
  // directly against the API), it falls back to advanced/raw mode with
  // the exact stored string instead of guessing.
  function handleEdit(s: Schedule) {
    setEditingId(s.id);
    setScannerAgentId(s.scanner_agent_id);
    setTargetSpec(s.target_spec);
    setPortSpec(s.port_spec);
    setScheduleType(s.schedule_type);

    if (s.schedule_type === "interval") {
      setIntervalMinutes(s.interval_minutes ?? 60);
    } else if (s.schedule_type === "once") {
      setRunAt(s.run_at ? utcIsoToZonedDateTimeLocal(s.run_at, timezone) : "");
    } else if (s.cron_expression) {
      const parsed = parseCronForBuilder(s.cron_expression);
      if (parsed) {
        const { time: localTime, dayShift } = utcHourMinuteToZonedTime(parsed.hour, parsed.minute, timezone);
        setAdvancedCron(false);
        setRepeatMode(parsed.repeatMode);
        setTime(localTime);
        if (parsed.repeatMode === "days" && parsed.days) {
          setSelectedDays(new Set(parsed.days.map((d) => shiftWeekday(d, dayShift))));
        }
        if (parsed.repeatMode === "monthly" && parsed.monthlyWeekday !== null && parsed.monthlyOccurrence !== null) {
          setMonthlyWeekday(shiftWeekday(parsed.monthlyWeekday, dayShift));
          setMonthlyOccurrence(parsed.monthlyOccurrence);
        }
      } else {
        setAdvancedCron(true);
        setRawCronExpression(s.cron_expression);
      }
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!scannerAgentId || !targetSpec.trim() || !portSpec.trim()) return;

    if (editingId) {
      const base = { targetSpec: targetSpec.trim(), portSpec: portSpec.trim(), scannerAgentId };
      if (scheduleType === "interval") {
        await api.updateSchedule(editingId, { ...base, intervalMinutes });
      } else if (scheduleType === "once") {
        if (!runAt) return;
        const [datePart, timePart] = runAt.split("T");
        await api.updateSchedule(editingId, { ...base, runAt: zonedDateTimeToUtcIso(datePart, timePart, timezone) });
      } else {
        const cronExpression = advancedCron ? rawCronExpression.trim() : generatedCron;
        if (!cronExpression) return;
        await api.updateSchedule(editingId, { ...base, cronExpression });
      }
      resetForm();
      await load();
      return;
    }

    if (scheduleType === "interval") {
      await api.createSchedule({
        scheduleType: "interval",
        scannerAgentId,
        targetSpec: targetSpec.trim(),
        portSpec: portSpec.trim(),
        intervalMinutes,
      });
    } else if (scheduleType === "once") {
      if (!runAt) return;
      // datetime-local's raw value ("YYYY-MM-DDTHH:MM") has no timezone of
      // its own - reinterpreted here as a wall-clock pick in the user's
      // preferred timezone (falling back to the browser's own local zone)
      // and converted to the correct UTC instant, rather than treating the
      // raw digits as if they were already UTC.
      const [datePart, timePart] = runAt.split("T");
      await api.createSchedule({
        scheduleType: "once",
        scannerAgentId,
        targetSpec: targetSpec.trim(),
        portSpec: portSpec.trim(),
        runAt: zonedDateTimeToUtcIso(datePart, timePart, timezone),
      });
    } else {
      const cronExpression = advancedCron ? rawCronExpression.trim() : generatedCron;
      if (!cronExpression) return;
      await api.createSchedule({
        scheduleType: "cron",
        scannerAgentId,
        targetSpec: targetSpec.trim(),
        portSpec: portSpec.trim(),
        cronExpression,
      });
    }
    setTargetSpec("");
    setPortSpec("");
    setRunAt("");
    await load();
  }

  async function toggleEnabled(s: Schedule) {
    await api.setScheduleEnabled(s.id, !s.enabled);
    await load();
  }

  async function remove(s: Schedule) {
    await api.deleteSchedule(s.id);
    await load();
  }

  const scannerFiltered =
    scannerFilterIds.length === 0 ? schedules : schedules.filter((s) => scannerFilterIds.includes(s.scanner_agent_id));
  const activeSchedules = scannerFiltered.filter((s) => scheduleStatus(s) === "active");
  const doneSchedules = scannerFiltered.filter((s) => scheduleStatus(s) === "done");
  const pausedSchedules = scannerFiltered.filter((s) => scheduleStatus(s) === "paused");

  function sortedGroup(group: Schedule[]): Schedule[] {
    return [...group].sort((a, b) => compareSchedules(a, b, sortKey, sortDirection));
  }

  const sharedHeaders = (
    <>
      <th onClick={() => setSort("target_spec")}>Target{sortIndicator("target_spec")}</th>
      <th onClick={() => setSort("port_spec")}>Ports{sortIndicator("port_spec")}</th>
      <th onClick={() => setSort("schedule")}>Schedule{sortIndicator("schedule")}</th>
      <th onClick={() => setSort("scanner_agent_name")}>Scanner{sortIndicator("scanner_agent_name")}</th>
      <th onClick={() => setSort("next_run_at")}>Next run{sortIndicator("next_run_at")}</th>
      <th onClick={() => setSort("last_run_at")}>Last run{sortIndicator("last_run_at")}</th>
      {isAdmin && <th>Actions</th>}
    </>
  );

  function sharedCells(s: Schedule) {
    return (
      <>
        <td>{s.target_spec}</td>
        <td>{s.port_spec}</td>
        <td>
          {s.schedule_type === "interval" ? (
            `every ${s.interval_minutes} min`
          ) : s.schedule_type === "once" ? (
            `once at ${s.run_at ? formatDateTime(s.run_at, me.preferences) : "?"}`
          ) : (
            <span className="fingerprint" title="cron expression, UTC">
              {s.cron_expression}
            </span>
          )}
        </td>
        <td>{s.scanner_agent_name ?? "?"}</td>
        <td>
          {/* A fired "once" schedule keeps its original run_at as
              next_run_at (see scheduler.ts) - showing that stale past
              date under "Next run" would look like a bug, so once it's
              done, there simply isn't one. */}
          {scheduleStatus(s) === "done" ? "-" : formatDateTime(s.next_run_at, me.preferences)}
        </td>
        <td>{s.last_run_at ? formatDateTime(s.last_run_at, me.preferences) : "never"}</td>
        {isAdmin && (
          <td>
            <div className="actions-cell">
              <button className="btn-icon-label" onClick={() => handleEdit(s)}>
                <IconEdit /> Edit
              </button>
              <button className="btn-icon-label" onClick={() => toggleEnabled(s)}>
                {s.enabled ? (
                  <>
                    <IconPause /> Pause
                  </>
                ) : (
                  <>
                    <IconPlay /> {s.schedule_type === "once" && s.last_run_at ? "Run again" : "Activate"}
                  </>
                )}
              </button>
              <button className="btn-icon-label" onClick={() => remove(s)}>
                <IconTrash /> Delete
              </button>
            </div>
          </td>
        )}
      </>
    );
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Schedule Scans</h2>

      {!isAdmin ? null : agents.length === 0 && !loading ? (
        <p className="empty">
          <Link to="/agents">Create a scanner agent</Link> first before a schedule can be created.
        </p>
      ) : (
        <form className="schedule-form" onSubmit={handleCreate}>
          <label>
            Scanner
            <select value={scannerAgentId} onChange={(e) => setScannerAgentId(e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Target
            <input placeholder="192.168.1.0/24 or 2001:db8::1" value={targetSpec} onChange={(e) => setTargetSpec(e.target.value)} />
          </label>
          <label>
            Ports
            <input placeholder="1-1000" value={portSpec} onChange={(e) => setPortSpec(e.target.value)} />
          </label>
          <label>
            Schedule type
            <select
              value={scheduleType}
              disabled={editingId !== null}
              onChange={(e) => setScheduleType(e.target.value as "interval" | "cron" | "once")}
            >
              <option value="interval">Every X minutes</option>
              <option value="cron">Fixed time(s)</option>
              <option value="once">Only once</option>
            </select>
          </label>
          {editingId !== null && (
            <p className="empty">Type can't be changed here - delete and recreate this schedule to change it.</p>
          )}

          {scheduleType === "interval" ? (
            <label>
              Interval (minutes)
              <input
                type="number"
                min={1}
                value={intervalMinutes}
                onChange={(e) => setIntervalMinutes(parseInt(e.target.value, 10) || 1)}
              />
            </label>
          ) : scheduleType === "once" ? (
            <label>
              Run at ({timezone})
              <input type="datetime-local" value={runAt} onChange={(e) => setRunAt(e.target.value)} />
            </label>
          ) : advancedCron ? (
            <label>
              Cron expression (UTC)
              <input
                placeholder="0 9 * * 1-5"
                value={rawCronExpression}
                onChange={(e) => setRawCronExpression(e.target.value)}
              />
            </label>
          ) : (
            <>
              <label>
                Repeats
                <select value={repeatMode} onChange={(e) => setRepeatMode(e.target.value as "daily" | "days" | "monthly")}>
                  <option value="daily">Every day</option>
                  <option value="days">On specific days</option>
                  <option value="monthly">Monthly, on a specific weekday</option>
                </select>
              </label>
              <label>
                Time ({timezone})
                <input type="time" value={time} onChange={(e) => setTime(e.target.value)} />
              </label>
              {repeatMode === "days" && (
                <div className="day-picker">
                  {DAY_LABELS.map((label, day) => (
                    <label key={day} className="day-picker-item">
                      <input type="checkbox" checked={selectedDays.has(day)} onChange={() => toggleDay(day)} />
                      {label}
                    </label>
                  ))}
                </div>
              )}
              {repeatMode === "monthly" && (
                <>
                  <label>
                    Occurrence
                    <select value={monthlyOccurrence} onChange={(e) => setMonthlyOccurrence(e.target.value)}>
                      <option value="1">1st</option>
                      <option value="2">2nd</option>
                      <option value="3">3rd</option>
                      <option value="4">4th</option>
                      <option value="L">Last</option>
                    </select>
                  </label>
                  <label>
                    Weekday
                    <select value={monthlyWeekday} onChange={(e) => setMonthlyWeekday(parseInt(e.target.value, 10))}>
                      {DAY_LABELS.map((label, day) => (
                        <option key={day} value={day}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </label>
                </>
              )}
            </>
          )}

          <button type="submit" className="btn-icon-label">
            {editingId !== null ? (
              <>
                <IconSave /> Save changes
              </>
            ) : (
              <>
                <IconPlus /> Create
              </>
            )}
          </button>
          {editingId !== null && (
            <button type="button" className="link-button btn-icon-label" onClick={resetForm}>
              <IconX /> Cancel
            </button>
          )}

          {scheduleType === "cron" && (
            <div className="cron-preview host-meta">
              {advancedCron ? (
                <button type="button" className="link-button" onClick={() => setAdvancedCron(false)}>
                  use the simple builder instead
                </button>
              ) : (
                <>
                  Cron (UTC equivalent of {time} {timezone}):{" "}
                  <span className="fingerprint">{generatedCron}</span>
                  <br />
                  A cron expression has no timezone of its own, so this is converted using{" "}
                  {timezone}'s <em>current</em> UTC offset - if that offset changes later
                  (daylight saving), delete and recreate this schedule to pick up the new one. ·{" "}
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      setRawCronExpression(generatedCron);
                      setAdvancedCron(true);
                    }}
                  >
                    edit as raw cron expression
                  </button>
                </>
              )}
            </div>
          )}
        </form>
      )}

      {loading ? (
        <p>Loading...</p>
      ) : schedules.length === 0 ? (
        <p className="empty">No scheduled scans created yet.</p>
      ) : (
        <>
          <label className="hide-empty-toggle push-right">
            Scanner
            <ScannerMultiSelect agents={agents} selectedIds={scannerFilterIds} onChange={setScannerFilterIds} align="right" />
          </label>

          <h3>Active ({activeSchedules.length})</h3>
          {activeSchedules.length === 0 ? (
            <p className="empty">No active schedules.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>{sharedHeaders}</tr>
              </thead>
              <tbody>
                {sortedGroup(activeSchedules).map((s) => (
                  <tr key={s.id}>{sharedCells(s)}</tr>
                ))}
              </tbody>
            </table>
          )}

          <h3>Done ({doneSchedules.length})</h3>
          {doneSchedules.length === 0 ? (
            <p className="empty">No one-time schedules have fired yet.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>{sharedHeaders}</tr>
              </thead>
              <tbody>
                {sortedGroup(doneSchedules).map((s) => (
                  <tr key={s.id}>{sharedCells(s)}</tr>
                ))}
              </tbody>
            </table>
          )}

          <h3>Paused ({pausedSchedules.length})</h3>
          {pausedSchedules.length === 0 ? (
            <p className="empty">No paused schedules.</p>
          ) : (
            <table className="sortable">
              <thead>
                <tr>{sharedHeaders}</tr>
              </thead>
              <tbody>
                {sortedGroup(pausedSchedules).map((s) => (
                  <tr key={s.id}>{sharedCells(s)}</tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
