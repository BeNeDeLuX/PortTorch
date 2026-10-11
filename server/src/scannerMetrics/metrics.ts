import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings } from "../settings/appSettings";
import { dispatchWebhook } from "../webhooks/dispatch";

// Scanner host metrics: what a scanner reports about its own machine once a
// minute (see scanner/internal/hostmetrics), stored for the per-scanner
// charts and rolled up hourly for the long ranges.

export const sampleSchema = z.object({
  at: z.string().datetime({ offset: true }),
  cpuPercent: z.number().min(0).max(100),
  memUsedBytes: z.number().int().min(0),
  memTotalBytes: z.number().int().min(0),
  netRxBytesPerSec: z.number().min(0),
  netTxBytesPerSec: z.number().min(0),
  load1: z.number().min(0),
  scansRunning: z.number().int().min(0).max(1000),
});

// A scanner buffers two hours while the webserver is away; anything much
// beyond that is not a delivery delay but a wrong clock.
export const metricsBatchSchema = z.object({ samples: z.array(sampleSchema).max(500) });
const ACCEPT_PAST_MS = 26 * 60 * 60 * 1000;
const ACCEPT_FUTURE_MS = 5 * 60 * 1000;

export async function storeSamples(scannerAgentId: string, samples: z.infer<typeof sampleSchema>[], now = new Date()): Promise<{ stored: number; dropped: number }> {
  const valid = samples.filter((s) => {
    const t = Date.parse(s.at);
    return t >= now.getTime() - ACCEPT_PAST_MS && t <= now.getTime() + ACCEPT_FUTURE_MS;
  });
  if (valid.length > 0) {
    await db
      .insertInto("scanner_metrics")
      .values(
        valid.map((s) => ({
          scanner_agent_id: scannerAgentId,
          at: s.at,
          cpu_percent: s.cpuPercent,
          mem_used_bytes: s.memUsedBytes,
          mem_total_bytes: s.memTotalBytes,
          net_rx_bps: s.netRxBytesPerSec,
          net_tx_bps: s.netTxBytesPerSec,
          load1: s.load1,
          scans_running: s.scansRunning,
        }))
      )
      // A batch re-sent after a lost response carries samples already
      // stored; keep the first copy.
      .onConflict((oc) => oc.columns(["scanner_agent_id", "at"]).doNothing())
      .execute();
  }
  return { stored: valid.length, dropped: samples.length - valid.length };
}

// Rolls every complete hour still covered by raw samples into the hourly
// table, then trims both tables to their retention. Recomputing the hours
// rather than tracking which were done makes it idempotent, and a sample
// that arrives late (a scanner catching up after an outage) simply lands
// in the next roll-up of its hour.
export async function rollupAndPrune(now = new Date()): Promise<{ hours: number; rawDeleted: number; hourlyDeleted: number }> {
  const { scannerMetricsRawDays, scannerMetricsHourlyDays } = await getAppSettings();
  const rolled = await sql`
    INSERT INTO scanner_metrics_hourly (
      scanner_agent_id, hour, samples, cpu_avg, cpu_max, mem_used_avg, mem_used_max, mem_total,
      net_rx_avg, net_rx_max, net_tx_avg, net_tx_max, load1_avg, scans_max
    )
    SELECT scanner_agent_id, date_trunc('hour', at), count(*), avg(cpu_percent), max(cpu_percent),
           avg(mem_used_bytes), max(mem_used_bytes), max(mem_total_bytes),
           avg(net_rx_bps), max(net_rx_bps), avg(net_tx_bps), max(net_tx_bps), avg(load1), max(scans_running)
    FROM scanner_metrics
    WHERE at < date_trunc('hour', ${now.toISOString()}::timestamptz)
    GROUP BY scanner_agent_id, date_trunc('hour', at)
    ON CONFLICT (scanner_agent_id, hour) DO UPDATE SET
      samples = excluded.samples, cpu_avg = excluded.cpu_avg, cpu_max = excluded.cpu_max,
      mem_used_avg = excluded.mem_used_avg, mem_used_max = excluded.mem_used_max, mem_total = excluded.mem_total,
      net_rx_avg = excluded.net_rx_avg, net_rx_max = excluded.net_rx_max,
      net_tx_avg = excluded.net_tx_avg, net_tx_max = excluded.net_tx_max,
      load1_avg = excluded.load1_avg, scans_max = excluded.scans_max
  `.execute(db);
  const raw = await db
    .deleteFrom("scanner_metrics")
    .where("at", "<", new Date(now.getTime() - scannerMetricsRawDays * 86_400_000))
    .executeTakeFirst();
  const hourly = await db
    .deleteFrom("scanner_metrics_hourly")
    .where("hour", "<", new Date(now.getTime() - scannerMetricsHourlyDays * 86_400_000))
    .executeTakeFirst();
  return { hours: Number(rolled.numAffectedRows ?? 0n), rawDeleted: Number(raw.numDeletedRows), hourlyDeleted: Number(hourly.numDeletedRows) };
}

export const RANGES = { "24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90, "365d": 365 } as const;
export type MetricsRange = keyof typeof RANGES;
// About this many points per chart, whatever the range - enough to read a
// shape, few enough to draw.
const TARGET_POINTS = 300;

export interface MetricsPoint {
  t: string;
  cpu: number;
  cpuMax: number;
  memUsed: number;
  memMax: number;
  memTotal: number;
  rx: number;
  rxMax: number;
  tx: number;
  txMax: number;
  load1: number;
  scans: number;
}

// The points for one scanner's charts. Ranges within the raw retention read
// the minute samples, longer ones the hourly roll-up - each bucketed so a
// chart has about TARGET_POINTS points. Maxima travel with averages, so a
// one-minute spike is still visible on a 30-day chart.
export async function metricsSeries(scannerAgentId: string, range: MetricsRange, now = new Date()) {
  const { scannerMetricsRawDays } = await getAppSettings();
  const days = RANGES[range];
  const from = new Date(now.getTime() - days * 86_400_000);
  const useRaw = days <= scannerMetricsRawDays;
  const bucketSeconds = Math.max(useRaw ? 60 : 3600, Math.ceil((days * 86_400) / TARGET_POINTS / 60) * 60);
  const bucket = sql`make_interval(secs => ${bucketSeconds})`;

  const { rows } = useRaw
    ? await sql<Record<string, unknown>>`
        SELECT date_bin(${bucket}, at, ${from.toISOString()}::timestamptz) AS t,
               avg(cpu_percent) AS cpu, max(cpu_percent) AS cpu_max,
               avg(mem_used_bytes) AS mem_used, max(mem_used_bytes) AS mem_max, max(mem_total_bytes) AS mem_total,
               avg(net_rx_bps) AS rx, max(net_rx_bps) AS rx_max, avg(net_tx_bps) AS tx, max(net_tx_bps) AS tx_max,
               avg(load1) AS load1, max(scans_running) AS scans
        FROM scanner_metrics
        WHERE scanner_agent_id = ${scannerAgentId} AND at >= ${from.toISOString()}
        GROUP BY 1 ORDER BY 1
      `.execute(db)
    : // The roll-up only covers complete hours, and only as of its last
      // run - so the hours after the newest rolled-up one are aggregated
      // from the minute samples here, or a long-range chart would always
      // end up to an hour early (and up to a day after a restart).
      await sql<Record<string, unknown>>`
        WITH rolled AS (
          SELECT max(hour) AS last FROM scanner_metrics_hourly WHERE scanner_agent_id = ${scannerAgentId}
        ),
        fresh AS (
          SELECT date_trunc('hour', at) AS hour,
                 avg(cpu_percent) AS cpu_avg, max(cpu_percent) AS cpu_max,
                 avg(mem_used_bytes) AS mem_used_avg, max(mem_used_bytes) AS mem_used_max, max(mem_total_bytes) AS mem_total,
                 avg(net_rx_bps) AS net_rx_avg, max(net_rx_bps) AS net_rx_max,
                 avg(net_tx_bps) AS net_tx_avg, max(net_tx_bps) AS net_tx_max,
                 avg(load1) AS load1_avg, max(scans_running) AS scans_max
          FROM scanner_metrics, rolled
          WHERE scanner_agent_id = ${scannerAgentId} AND at >= ${from.toISOString()}
            AND (rolled.last IS NULL OR at >= rolled.last + interval '1 hour')
          GROUP BY 1
        ),
        src AS (
          SELECT hour, cpu_avg, cpu_max, mem_used_avg, mem_used_max, mem_total,
                 net_rx_avg, net_rx_max, net_tx_avg, net_tx_max, load1_avg, scans_max
          FROM scanner_metrics_hourly
          WHERE scanner_agent_id = ${scannerAgentId} AND hour >= ${from.toISOString()}
          UNION ALL
          SELECT * FROM fresh
        )
        SELECT date_bin(${bucket}, hour, ${from.toISOString()}::timestamptz) AS t,
               avg(cpu_avg) AS cpu, max(cpu_max) AS cpu_max,
               avg(mem_used_avg) AS mem_used, max(mem_used_max) AS mem_max, max(mem_total) AS mem_total,
               avg(net_rx_avg) AS rx, max(net_rx_max) AS rx_max, avg(net_tx_avg) AS tx, max(net_tx_max) AS tx_max,
               avg(load1_avg) AS load1, max(scans_max) AS scans
        FROM src
        GROUP BY 1 ORDER BY 1
      `.execute(db);

  // Every aggregate is a numeric or bigint the driver hands back as a
  // string - converted here, once (see server/CLAUDE.md's Scan History).
  const n = (v: unknown) => (v === null || v === undefined ? 0 : Number(v));
  const points: MetricsPoint[] = rows.map((r) => ({
    t: new Date(r.t as string).toISOString(),
    cpu: n(r.cpu),
    cpuMax: n(r.cpu_max),
    memUsed: n(r.mem_used),
    memMax: n(r.mem_max),
    memTotal: n(r.mem_total),
    rx: n(r.rx),
    rxMax: n(r.rx_max),
    tx: n(r.tx),
    txMax: n(r.tx_max),
    load1: n(r.load1),
    scans: n(r.scans),
  }));

  // The scans that ran in the window, so a chart can say which scan made
  // the load it shows.
  const scans = await db
    .selectFrom("scan_jobs")
    .select(["id", "target_spec", "port_spec", "status", "started_at", "finished_at"])
    .where("scanner_agent_id", "=", scannerAgentId)
    .where("started_at", "<=", now)
    .where((eb) => eb.or([eb("finished_at", "is", null), eb("finished_at", ">=", from)]))
    .where("started_at", ">=", new Date(from.getTime() - 30 * 86_400_000))
    .orderBy("started_at")
    .limit(500)
    .execute();

  const latest = await db
    .selectFrom("scanner_metrics")
    .selectAll()
    .where("scanner_agent_id", "=", scannerAgentId)
    .orderBy("at", "desc")
    .limit(1)
    .executeTakeFirst();

  return {
    range,
    from: from.toISOString(),
    to: now.toISOString(),
    bucketSeconds,
    source: useRaw ? ("minute" as const) : ("hourly" as const),
    points,
    scans: scans.map((s) => ({
      id: s.id,
      targetSpec: s.target_spec,
      portSpec: s.port_spec,
      status: s.status,
      startedAt: s.started_at,
      finishedAt: s.finished_at,
    })),
    latest: latest
      ? {
          at: latest.at,
          cpuPercent: latest.cpu_percent,
          memUsedBytes: Number(latest.mem_used_bytes),
          memTotalBytes: Number(latest.mem_total_bytes),
          netRxBytesPerSec: latest.net_rx_bps,
          netTxBytesPerSec: latest.net_tx_bps,
          load1: latest.load1,
          scansRunning: latest.scans_running,
        }
      : null,
  };
}

// Sustained pressure, not a spike: the average over the last 15 minutes,
// and only with enough samples in that window to call it an average.
const PRESSURE_WINDOW_MINUTES = 15;
const PRESSURE_MIN_SAMPLES = 10;
export const PRESSURE_CPU_PERCENT = 90;
export const PRESSURE_MEM_PERCENT = 90;

// scanner.resource_pressure - come-and-go, like scanner.offline: it fires
// once when a scanner's host has run at its limit for a sustained period,
// and is armed again once the pressure is gone, so the next episode alerts
// rather than being silenced by this one.
export async function checkResourcePressure(now = new Date()): Promise<number> {
  const since = new Date(now.getTime() - PRESSURE_WINDOW_MINUTES * 60_000);
  const { rows } = await sql<{ id: string; name: string; sent: Date | null; samples: string; cpu: number | null; mem_pct: number | null }>`
    SELECT sa.id, sa.name, sa.resource_alert_sent_at AS sent, count(m.at) AS samples,
           avg(m.cpu_percent) AS cpu,
           avg(m.mem_used_bytes::float / nullif(m.mem_total_bytes, 0) * 100) AS mem_pct
    FROM scanner_agents sa
    LEFT JOIN scanner_metrics m ON m.scanner_agent_id = sa.id AND m.at >= ${since.toISOString()}
    WHERE sa.revoked_at IS NULL
    GROUP BY sa.id
  `.execute(db);

  let fired = 0;
  for (const r of rows) {
    const enough = Number(r.samples) >= PRESSURE_MIN_SAMPLES;
    const cpu = r.cpu === null ? 0 : Number(r.cpu);
    const mem = r.mem_pct === null ? 0 : Number(r.mem_pct);
    const pressured = enough && (cpu >= PRESSURE_CPU_PERCENT || mem >= PRESSURE_MEM_PERCENT);
    if (pressured && !r.sent) {
      const what = [cpu >= PRESSURE_CPU_PERCENT ? `CPU ${cpu.toFixed(0)}%` : null, mem >= PRESSURE_MEM_PERCENT ? `memory ${mem.toFixed(0)}%` : null]
        .filter(Boolean)
        .join(" and ");
      await dispatchWebhook(
        "scanner.resource_pressure",
        `Scanner "${r.name}" has averaged ${what} over the last ${PRESSURE_WINDOW_MINUTES} minutes - scans on it may slow down or fail. Lower its masscan rate or concurrent scans, or give the host more capacity.`,
        { scanner_agent_id: r.id, scanner_agent_name: r.name, cpu_percent: Math.round(cpu), memory_percent: Math.round(mem), window_minutes: PRESSURE_WINDOW_MINUTES },
        { scannerAgentId: r.id }
      );
      await db.updateTable("scanner_agents").set({ resource_alert_sent_at: now }).where("id", "=", r.id).execute();
      fired++;
    } else if (!pressured && r.sent && enough) {
      // Only cleared on evidence: a scanner that stopped reporting is
      // scanner.offline's business, not a recovery.
      await db.updateTable("scanner_agents").set({ resource_alert_sent_at: null }).where("id", "=", r.id).execute();
    }
  }
  return fired;
}

export function startScannerMetrics(): void {
  const rollup = () =>
    rollupAndPrune().catch((err) => logger.error({ event: "scanner_metrics.rollup_failed", err: err instanceof Error ? err.message : String(err) }));
  const pressure = () =>
    checkResourcePressure().catch((err) => logger.error({ event: "scanner_metrics.pressure_check_failed", err: err instanceof Error ? err.message : String(err) }));
  // Once shortly after start as well: an hourly interval alone would leave
  // a restarted process without a roll-up for its first hour.
  setTimeout(rollup, 30_000);
  setInterval(rollup, 60 * 60 * 1000);
  setInterval(pressure, 5 * 60 * 1000);
}
