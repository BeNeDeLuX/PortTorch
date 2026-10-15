import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { getAppSettings } from "../settings/appSettings";
import { toDateOnlyString } from "../lib/dateOnly";
import { compareSemver } from "../scannerUpdate/githubSync";
import { NOT_A_LIVE_RISK_STATES, cveNotTriaged, cveRuleNotTriaged } from "../findingTriage/sqlFilters";
import { measureStorage } from "../webserverStorage/storage";
import { dispatchWebhook } from "../webhooks/dispatch";
import { computeDigest } from "./routes";

// The week at a glance, for the people responsible rather than the people
// operating: the daily digest lists every change, this says where the
// fleet stands and whether it is getting better or worse. Sent as
// report.weekly on Mondays at the daily digest's hour, to every channel
// subscribed to it - email and webhook alike, like every other event.
//
// Every figure is computed fleet-wide (no session, so no scanner
// restriction), each with last week's value beside it where "better or
// worse" is a meaningful question.

export interface WeeklyReport {
  from: string;
  to: string;
  hosts: { total: number; newThisWeek: number; newLastWeek: number };
  changes: { newHosts: number; changedHosts: number };
  scans: { completed: number; completedLastWeek: number; failed: number };
  exposure: { hostsWithKev: number; hostsWithCritical: number; longUptime: number };
  scanners: { live: number; offline: string[]; behind: string[]; idle: string[]; latestVersion: string | null };
  storage: { diskFreePercent: number | null; dbBytes: number; dbBytesWeekAgo: number | null };
}

const WEEK = 7 * 86_400_000;

export async function computeWeeklyReport(now = new Date()): Promise<WeeklyReport> {
  const from = new Date(now.getTime() - WEEK);
  const before = new Date(now.getTime() - 2 * WEEK);
  const { scannerOfflineThresholdMinutes } = await getAppSettings();

  const [hostCounts, scanCounts, exposure, agents, release, digest, storage, dbWeekAgo] = await Promise.all([
    sql<{ total: string; new_this: string; new_last: string }>`
      SELECT count(*) AS total,
             count(*) FILTER (WHERE first_seen_at >= ${from.toISOString()}) AS new_this,
             count(*) FILTER (WHERE first_seen_at >= ${before.toISOString()} AND first_seen_at < ${from.toISOString()}) AS new_last
      FROM hosts WHERE retired_at IS NULL
    `.execute(db),
    sql<{ completed: string; completed_last: string; failed: string }>`
      SELECT count(*) FILTER (WHERE status = 'completed' AND finished_at >= ${from.toISOString()}) AS completed,
             count(*) FILTER (WHERE status = 'completed' AND finished_at >= ${before.toISOString()} AND finished_at < ${from.toISOString()}) AS completed_last,
             count(*) FILTER (WHERE status = 'failed' AND finished_at >= ${from.toISOString()}) AS failed
      FROM scan_jobs
    `.execute(db),
    sql<{ kev: string; critical: string; long_uptime: string }>`
      WITH risk AS (
        SELECT h.id,
               bool_or(kc.cve_id IS NOT NULL) AS kev,
               max((cve_elem->>'cvssScore')::float) AS max_cvss
        FROM hosts h
        JOIN current_host_ports chp ON chp.host_id = h.id AND chp.state = 'open'
        JOIN cve_cache cc ON cc.cpe = ANY(chp.cpes)
        CROSS JOIN LATERAL jsonb_array_elements(cc.cves) AS cve_elem
        LEFT JOIN kev_cache kc ON kc.cve_id = cve_elem->>'id'
        WHERE h.retired_at IS NULL
          AND ${cveNotTriaged("h.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
          AND ${cveRuleNotTriaged("cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
        GROUP BY h.id
      )
      SELECT (SELECT count(*) FROM risk WHERE kev) AS kev,
             (SELECT count(*) FROM risk WHERE max_cvss >= 9) AS critical,
             (SELECT count(*) FROM hosts WHERE retired_at IS NULL AND boot_time <= now() - interval '180 days') AS long_uptime
    `.execute(db),
    db
      .selectFrom("scanner_agents")
      .select([
        "name",
        "version",
        "last_seen_at",
        "created_at",
        sql<Date | null>`(SELECT max(finished_at) FROM scan_jobs WHERE scan_jobs.scanner_agent_id = scanner_agents.id AND status = 'completed')`.as("last_completed"),
      ])
      .where("revoked_at", "is", null)
      .execute(),
    db.selectFrom("scanner_release_cache").select("latest_version").where("id", "=", 1).executeTakeFirst(),
    computeDigest(from, now, null),
    measureStorage(now),
    db
      .selectFrom("webserver_storage_samples")
      .select("db_bytes")
      .where("day", "<=", from.toISOString().slice(0, 10))
      .orderBy("day", "desc")
      .limit(1)
      .executeTakeFirst(),
  ]);

  const latest = release?.latest_version ?? null;
  const offlineCutoff = now.getTime() - scannerOfflineThresholdMinutes * 60_000;
  const h = hostCounts.rows[0];
  const s = scanCounts.rows[0];
  const e = exposure.rows[0];
  return {
    from: from.toISOString(),
    to: now.toISOString(),
    hosts: { total: Number(h.total), newThisWeek: Number(h.new_this), newLastWeek: Number(h.new_last) },
    changes: { newHosts: digest.newHosts.length, changedHosts: digest.changedHosts.length },
    scans: { completed: Number(s.completed), completedLastWeek: Number(s.completed_last), failed: Number(s.failed) },
    exposure: { hostsWithKev: Number(e.kev), hostsWithCritical: Number(e.critical), longUptime: Number(e.long_uptime) },
    scanners: {
      live: agents.length,
      offline: agents.filter((a) => a.last_seen_at && a.last_seen_at.getTime() < offlineCutoff).map((a) => a.name),
      behind: latest ? agents.filter((a) => a.version && compareSemver(latest, a.version) > 0).map((a) => `${a.name} (${a.version})`) : [],
      idle: agents
        .filter((a) => a.created_at.getTime() < from.getTime() && (!a.last_completed || a.last_completed.getTime() < from.getTime()))
        .map((a) => a.name),
      latestVersion: latest,
    },
    storage: {
      diskFreePercent: storage.diskFreeBytes !== null && storage.diskTotalBytes ? (100 * storage.diskFreeBytes) / storage.diskTotalBytes : null,
      dbBytes: storage.dbBytes,
      dbBytesWeekAgo: dbWeekAgo ? Number(dbWeekAgo.db_bytes) : null,
    },
  };
}

const delta = (now: number, then: number) => (now === then ? "same as last week" : `${now > then ? "+" : ""}${now - then} vs last week`);
const mb = (n: number) => `${(n / 1024 ** 2).toFixed(0)} MB`;

// Plain text, for the same reason as the daily digest: email has no HTML
// body here, and a webhook channel shows the message as it is.
export function formatWeeklyReport(r: WeeklyReport): string {
  const lines = [
    `PortTorch weekly report - ${r.from.slice(0, 10)} to ${r.to.slice(0, 10)}`,
    "",
    "Fleet",
    `  ${r.hosts.total} hosts, ${r.hosts.newThisWeek} new this week (${delta(r.hosts.newThisWeek, r.hosts.newLastWeek)})`,
    `  ${r.changes.changedHosts} hosts with port changes`,
    "",
    "Exposure",
    `  ${r.exposure.hostsWithKev} hosts with a known exploited CVE (CISA KEV)`,
    `  ${r.exposure.hostsWithCritical} hosts with a critical CVE (CVSS 9+)`,
    `  ${r.exposure.longUptime} devices up longer than 180 days - likely unpatched`,
    "",
    "Scanning",
    `  ${r.scans.completed} scans completed (${delta(r.scans.completed, r.scans.completedLastWeek)}), ${r.scans.failed} failed`,
    `  ${r.scanners.live} scanners${r.scanners.latestVersion ? `, latest release v${r.scanners.latestVersion}` : ""}`,
  ];
  if (r.scanners.offline.length > 0) lines.push(`  offline: ${r.scanners.offline.join(", ")}`);
  if (r.scanners.behind.length > 0) lines.push(`  not on the latest release: ${r.scanners.behind.join(", ")}`);
  if (r.scanners.idle.length > 0) lines.push(`  no completed scan this week: ${r.scanners.idle.join(", ")}`);
  lines.push("", "Webserver");
  lines.push(
    `  ${r.storage.diskFreePercent !== null ? `${r.storage.diskFreePercent.toFixed(0)}% disk free, ` : ""}database ${mb(r.storage.dbBytes)}` +
      (r.storage.dbBytesWeekAgo !== null ? ` (${r.storage.dbBytes >= r.storage.dbBytesWeekAgo ? "+" : ""}${mb(r.storage.dbBytes - r.storage.dbBytesWeekAgo)} this week)` : "")
  );
  return lines.join("\n");
}

// Mondays, at the daily digest's hour, once per week.
export async function weeklyTick(now = new Date()): Promise<boolean> {
  const { digestEmailHourUtc } = await getAppSettings();
  if (now.getUTCDay() !== 1 || now.getUTCHours() !== digestEmailHourUtc) return false;
  const week = now.toISOString().slice(0, 10);
  const state = await db.selectFrom("weekly_report_state").select("last_sent_week").where("id", "=", 1).executeTakeFirst();
  if (toDateOnlyString(state?.last_sent_week ?? null) === week) return false;
  const report = await computeWeeklyReport(now);
  await dispatchWebhook("report.weekly", formatWeeklyReport(report), { report });
  await db.updateTable("weekly_report_state").set({ last_sent_week: week }).where("id", "=", 1).execute();
  logger.info({ event: "weekly_report.sent", hosts: report.hosts.total, kev_hosts: report.exposure.hostsWithKev });
  return true;
}

export function startWeeklyReport(): void {
  setInterval(() => {
    weeklyTick().catch((err) => logger.error({ event: "weekly_report.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, 60 * 60_000);
}
