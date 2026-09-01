import { sql } from "kysely";
import { config } from "../config";
import { db } from "../db";
import { isStaleScanJob } from "../lib/staleness";
import { logger } from "../logger";
import { dispatchWebhook } from "./dispatch";
import { getAppSettings } from "../settings/appSettings";
import { computeNetworkCoverage } from "../networks/coverage";

// Far more frequent than the hourly certificate-expiry checks
// (webhooks/expiryAlerts.ts, settings/certExpiryAlert.ts) - unlike a
// slow-moving expiry countdown, a scan that's died mid-run or a queue
// that's stopped draining is actionable right away, not just "worth
// knowing about sometime today".
const CHECK_INTERVAL_MS = 5 * 60_000;

// The Fleet Health page (frontend/src/pages/FleetHealth.tsx) surfaces
// most of these conditions passively, for whoever happens to load that
// page - this is the active counterpart, pushing scan.stale,
// scan_queue.backlog, scanner.offline and host.disappeared webhooks so
// nobody has to be looking.
export function startOperationalAlerts(): void {
  setInterval(() => {
    tick().catch((err) =>
      logger.error({ event: "webhook.operational_check_failed", err: err instanceof Error ? err.message : String(err) })
    );
  }, CHECK_INTERVAL_MS);
}

// Exported so the integration tests can drive one full pass
// deterministically instead of waiting on the five-minute interval - same
// "expose the scheduled job's own logic" shape as runRetentionSweep.
export async function runOperationalAlertChecks(): Promise<void> {
  await tick();
}

async function tick(): Promise<void> {
  await checkStaleScans();
  await checkQueueBacklog();
  await checkOfflineScanners();
  await checkDisappearedHosts();
  await checkNetworkCoverage();
  await checkSharedSSHKeys();
}

// Fires scan.stale once per scan_jobs row (stale_alert_sent_at) - a job
// stuck in "running" past app_settings.stale_scan_threshold_minutes with
// no recent progress heartbeat almost always means the scanner process
// died mid-scan (see lib/staleness.ts's isStaleScanJob and the existing
// is_stale flag on GET /api/scan-jobs/active - same activity-aware check,
// so this never fires for a scan that's merely slow but still genuinely
// progressing). No need to ever clear the flag: a scan_jobs row is
// created fresh per scan and either finishes normally (leaving the
// "running" status this query filters on) or stays stuck forever, so
// "fire once, forever" is correct here, same idiom as
// tls_certificates.expiry_alert_sent_at.
async function checkStaleScans(): Promise<void> {
  const candidates = await db
    .selectFrom("scan_jobs")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .leftJoin("scan_job_progress", "scan_job_progress.scan_job_id", "scan_jobs.id")
    .select([
      "scan_jobs.id as id",
      "scan_jobs.target_spec as target_spec",
      "scan_jobs.port_spec as port_spec",
      "scan_jobs.started_at as started_at",
      "scanner_agents.name as scanner_agent_name",
      "scan_job_progress.updated_at as last_progress_at",
    ])
    .where("scan_jobs.status", "=", "running")
    .where("scan_jobs.stale_alert_sent_at", "is", null)
    .execute();
  const { staleScanThresholdMinutes } = await getAppSettings();

  for (const job of candidates) {
    if (!isStaleScanJob(job.started_at, job.last_progress_at, staleScanThresholdMinutes)) continue;

    const scannerLabel = job.scanner_agent_name ?? "an unknown scanner";
    const message = `Scan job on ${scannerLabel} targeting ${job.target_spec}:${job.port_spec} looks stalled - still "running" since ${new Date(job.started_at).toISOString()}`;

    await dispatchWebhook("scan.stale", message, {
      scan_job_id: job.id,
      scanner_agent_name: job.scanner_agent_name,
      target_spec: job.target_spec,
      port_spec: job.port_spec,
      started_at: job.started_at,
    });

    await db.updateTable("scan_jobs").set({ stale_alert_sent_at: new Date() }).where("id", "=", job.id).execute();
    logger.info({ event: "webhook.scan_stale_alerted", scan_job_id: job.id });
  }
}

// Fires scan_queue.backlog once per scanner agent whose oldest pending
// scan_requests row is older than config.queueBacklogThresholdMinutes -
// tracked on scanner_agents.queue_backlog_alert_sent_at (one flag per
// agent, not per request), since the backlog is one ongoing condition for
// that scanner, not N independent events. Unlike checkStaleScans above,
// this condition can come and go (the scanner catches up, then falls
// behind again later), so the flag is actively cleared once that agent no
// longer has an aged backlog - letting a future backlog alert again
// instead of being permanently silenced by one past incident.
async function checkQueueBacklog(): Promise<void> {
  const { queueBacklogThresholdMinutes } = await getAppSettings();
  const threshold = new Date(Date.now() - queueBacklogThresholdMinutes * 60_000);

  const backlogged = await db
    .selectFrom("scan_requests")
    .innerJoin("scanner_agents", "scanner_agents.id", "scan_requests.scanner_agent_id")
    .select([
      "scan_requests.scanner_agent_id as scanner_agent_id",
      "scanner_agents.name as scanner_agent_name",
      "scanner_agents.queue_backlog_alert_sent_at as queue_backlog_alert_sent_at",
      sql<number>`count(*)`.as("pending_count"),
      sql<Date>`min(scan_requests.created_at)`.as("oldest_created_at"),
    ])
    .where("scan_requests.status", "=", "pending")
    .where("scanner_agents.revoked_at", "is", null)
    .groupBy(["scan_requests.scanner_agent_id", "scanner_agents.name", "scanner_agents.queue_backlog_alert_sent_at"])
    .execute();

  const stillBackloggedIds: string[] = [];

  for (const row of backlogged) {
    if (new Date(row.oldest_created_at) > threshold) continue;
    // scan_requests.scanner_agent_id is nullable in general (a request
    // whose agent was later deleted), but the innerJoin on scanner_agents
    // above means every row here necessarily has one.
    stillBackloggedIds.push(row.scanner_agent_id!);
    if (row.queue_backlog_alert_sent_at) continue; // already alerted, still backlogged - don't repeat

    const pendingCount = Number(row.pending_count);
    const message = `Scanner "${row.scanner_agent_name}" has ${pendingCount} pending scan request(s) queued, oldest queued since ${new Date(row.oldest_created_at).toISOString()} - it may have stopped polling`;

    await dispatchWebhook("scan_queue.backlog", message, {
      scanner_agent_id: row.scanner_agent_id,
      scanner_agent_name: row.scanner_agent_name,
      pending_count: pendingCount,
      oldest_created_at: row.oldest_created_at,
    });

    await db
      .updateTable("scanner_agents")
      .set({ queue_backlog_alert_sent_at: new Date() })
      .where("id", "=", row.scanner_agent_id)
      .execute();
    logger.info({ event: "webhook.queue_backlog_alerted", scanner_agent_id: row.scanner_agent_id });
  }

  // Clear any previously-alerted agent that's no longer in the
  // still-backlogged set above (caught up, or its aged requests were
  // cancelled/claimed/deleted) - an empty exclusion list needs its own
  // branch since a plain "id not in ()" is invalid SQL.
  let clearQuery = db
    .updateTable("scanner_agents")
    .set({ queue_backlog_alert_sent_at: null })
    .where("queue_backlog_alert_sent_at", "is not", null);
  if (stillBackloggedIds.length > 0) {
    clearQuery = clearQuery.where("id", "not in", stillBackloggedIds);
  }
  await clearQuery.execute();
}

// Fires scanner.offline once per agent whose last authenticated request
// is older than app_settings.scanner_offline_threshold_minutes.
//
// This is the gap the other two checks above leave open: scan.stale only
// covers a job already stuck mid-run, and scan_queue.backlog only fires
// once work has actually piled up for that scanner - so an agent with no
// running scan and nothing queued (no schedules pointed at it, or all of
// them already fired) could be dead indefinitely with nothing said. Fleet
// Health shows it passively; this is the push counterpart.
//
// last_seen_at is written by apiKeyAuth.ts on *every* authenticated
// request, and a serve-mode scanner polls several endpoints continuously
// (StartPolling, StartCancelWatcher, StartUpdateWatcher), so a live
// scanner refreshes this far more often than any plausible threshold.
//
// A null last_seen_at is deliberately skipped rather than treated as
// infinitely stale: that means an agent whose API key was created but
// which has never once connected - an install in progress, not an
// outage. Same "absence is its own third state, not the extreme of the
// scale" reasoning as scanner_agents.version elsewhere.
//
// Come-and-go, like checkQueueBacklog: the flag is cleared once the agent
// reports in again, so a future outage alerts rather than being silenced
// forever by one past one.
async function checkOfflineScanners(): Promise<void> {
  const { scannerOfflineThresholdMinutes } = await getAppSettings();
  const threshold = new Date(Date.now() - scannerOfflineThresholdMinutes * 60_000);

  const offline = await db
    .selectFrom("scanner_agents")
    .select(["id", "name", "last_seen_at", "version", "offline_alert_sent_at"])
    .where("revoked_at", "is", null)
    .where("last_seen_at", "is not", null)
    .where("last_seen_at", "<", threshold)
    .execute();

  for (const agent of offline) {
    if (agent.offline_alert_sent_at) continue; // already alerted, still offline

    const lastSeen = new Date(agent.last_seen_at!).toISOString();
    const message = `Scanner "${agent.name}" has not reported in since ${lastSeen} (threshold ${scannerOfflineThresholdMinutes} minutes) - it may be stopped, crashed, or cut off from this webserver`;

    await dispatchWebhook("scanner.offline", message, {
      scanner_agent_id: agent.id,
      scanner_agent_name: agent.name,
      last_seen_at: agent.last_seen_at,
      version: agent.version,
      threshold_minutes: scannerOfflineThresholdMinutes,
    });

    await db.updateTable("scanner_agents").set({ offline_alert_sent_at: new Date().toISOString() }).where("id", "=", agent.id).execute();
    logger.info({ event: "webhook.scanner_offline_alerted", scanner_agent_id: agent.id, scanner_agent_name: agent.name });
  }

  // Anything previously alerted whose last_seen_at is now inside the
  // threshold has come back - clear it so the next outage alerts again.
  // Expressed as its own UPDATE rather than derived from the query above,
  // which only ever selected agents that are *currently* offline.
  const recovered = await db
    .updateTable("scanner_agents")
    .set({ offline_alert_sent_at: null })
    .where("offline_alert_sent_at", "is not", null)
    .where((eb) => eb.or([eb("last_seen_at", ">=", threshold), eb("last_seen_at", "is", null)]))
    .returning(["id", "name"])
    .execute();
  for (const agent of recovered) {
    logger.info({ event: "scanner.back_online", scanner_agent_id: agent.id, scanner_agent_name: agent.name });
  }
}

// Fires host.disappeared once per host not seen for
// app_settings.host_disappeared_threshold_days.
//
// Deliberately a periodic check rather than an ingest-time one, unlike
// port.closed: a host that has stopped responding produces no ingest
// request at all, so there is no write path that could ever notice it.
//
// The threshold is in days, not minutes like the scanner one, because the
// signal is fundamentally slower: hosts are only re-seen as often as
// something scans their range, so "not seen in 30 minutes" says nothing
// about a host, while "not seen in two weeks" does. It has to be
// comfortably longer than the interval of whatever schedule covers that
// host, or every host alerts between scans - which is exactly why it's an
// admin-visible setting rather than a constant.
//
// Only hosts that were seen at least once *before* the threshold are
// considered, via first_seen_at: a host discovered five minutes ago by a
// one-off ad-hoc scan of a range nothing else covers hasn't "disappeared"
// just because nothing has scanned it since.
async function checkDisappearedHosts(): Promise<void> {
  const { hostDisappearedThresholdDays } = await getAppSettings();
  const threshold = new Date(Date.now() - hostDisappearedThresholdDays * 24 * 60 * 60_000);

  const gone = await db
    .selectFrom("hosts")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select([
      "hosts.id as id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "hosts.last_seen_at as last_seen_at",
      "scanner_agents.name as scanner_agent_name",
    ])
    .where("hosts.disappeared_alert_sent_at", "is", null)
    .where("hosts.last_seen_at", "<", threshold)
    .where("hosts.first_seen_at", "<", threshold)
    // A retired host is one an operator has already accounted for. It
    // stays in the inventory with its full history; it just stops being
    // news that it isn't answering.
    .where("hosts.retired_at", "is", null)
    .execute();

  for (const host of gone) {
    const label = host.hostname || host.ip;
    const message = `Host ${label} has not been seen since ${new Date(host.last_seen_at).toISOString()} (threshold ${hostDisappearedThresholdDays} days) - decommissioned, or down`;

    await dispatchWebhook("host.disappeared", message, {
      host_id: host.id,
      ip: host.ip,
      hostname: host.hostname,
      last_seen_at: host.last_seen_at,
      scanner_agent_name: host.scanner_agent_name,
      threshold_days: hostDisappearedThresholdDays,
    });

    await db.updateTable("hosts").set({ disappeared_alert_sent_at: new Date().toISOString() }).where("id", "=", host.id).execute();
    logger.info({ event: "webhook.host_disappeared_alerted", host_id: host.id, ip: host.ip });
  }

  // Came back - a later scan updated last_seen_at. Cleared here rather
  // than in the ingest path so the reset lives next to the rule that set
  // it, and so it can't be missed by a code path that writes last_seen_at
  // without going through the host upsert.
  const returned = await db
    .updateTable("hosts")
    .set({ disappeared_alert_sent_at: null })
    .where("disappeared_alert_sent_at", "is not", null)
    .where("last_seen_at", ">=", threshold)
    .returning(["id", "ip"])
    .execute();
  for (const host of returned) {
    logger.info({ event: "host.reappeared", host_id: host.id, ip: host.ip });
  }
}

// Fires network.coverage_stale once per tracked range that no completed
// scan has touched within app_settings.network_coverage_stale_days.
//
// This is the one alert whose whole point is that nobody is looking: the
// Network Coverage page answers "which of my ranges is nobody scanning",
// and a range going unscanned is precisely the condition where nobody
// thinks to open that page. Every other check here has a passive
// counterpart on Fleet Health that someone might stumble across; this one
// does not.
//
// The rule is deliberately "not touched at all in the window" rather than
// a coverage percentage below some threshold. Partial coverage has a
// hundred legitimate shapes (a /16 whose populated half is swept nightly
// while the empty half never is), and any percentage cutoff would be a
// number nobody could justify. "Nothing scanned this range for N days" is
// unambiguous and actionable, and N is already an admin-visible setting.
//
// Coverage is computed by the same computeNetworkCoverage the page uses -
// deliberately not a second query that "checks the same thing", which is
// how the alert and the page would end up disagreeing.
//
// Come-and-go, like checkOfflineScanners: cleared once the range is
// covered again, so the next gap alerts rather than being silenced by
// this one.
async function checkNetworkCoverage(): Promise<void> {
  // null: an alert is not sent on any particular user's behalf, so it
  // sees every tracked range regardless of per-user scanner restrictions.
  const { staleDays, networks } = await computeNetworkCoverage(null);

  for (const network of networks) {
    const stale = network.covered_fraction === 0;
    if (!stale || network.coverage_alert_sent_at) continue;

    const lastCovered = network.last_covered_at
      ? `last covered ${new Date(network.last_covered_at).toISOString()}`
      : "never covered by any completed scan";
    const scope = network.scanner_agent_name ? ` (scanner "${network.scanner_agent_name}")` : "";
    const message = `Network "${network.label}" (${network.cidr})${scope} has not been scanned in the last ${staleDays} days - ${lastCovered}`;

    await dispatchWebhook("network.coverage_stale", message, {
      network_id: network.id,
      label: network.label,
      cidr: network.cidr,
      scanner_agent_name: network.scanner_agent_name,
      last_covered_at: network.last_covered_at,
      host_count: network.host_count,
      threshold_days: staleDays,
      // An unresolvable target (a DNS hostname, resolved scanner-side)
      // may in fact have covered this range - passed on so the alert is
      // as honest as the page is, rather than asserting more than the
      // webserver actually knows.
      opaque_scan_count: network.opaque_scan_count,
    });

    await db
      .updateTable("monitored_networks")
      .set({ coverage_alert_sent_at: new Date().toISOString() })
      .where("id", "=", network.id)
      .execute();
    logger.info({ event: "webhook.network_coverage_stale_alerted", network_id: network.id, cidr: network.cidr });
  }

  // Covered again - clear so a future gap alerts. Derived from the same
  // computed rows rather than a separate query, for the same reason the
  // alert itself is.
  const recovered = networks.filter((n) => n.covered_fraction > 0 && n.coverage_alert_sent_at);
  if (recovered.length > 0) {
    await db
      .updateTable("monitored_networks")
      .set({ coverage_alert_sent_at: null })
      .where(
        "id",
        "in",
        recovered.map((n) => n.id)
      )
      .execute();
    for (const network of recovered) {
      logger.info({ event: "network.coverage_restored", network_id: network.id, cidr: network.cidr });
    }
  }
}

// Fires ssh_key.shared when one SSH host key fingerprint turns up on more
// than one address - a cloned VM, a golden image that shipped its keys,
// or a genuinely shared private key.
//
// Counted in distinct addresses rather than distinct hosts rows for the
// same reason the SSH Host Keys page is: host identity is
// (ip, scanner_agent_id), so one machine two scanners can both reach is
// two rows legitimately serving the same key, and counting rows would
// alert on every multi-scanner deployment.
//
// State lives in its own ssh_shared_key_alerts table because the subject
// of the alert is a fingerprint, which belongs to no single row anywhere.
// Storing the count alongside it means a *growing* group alerts again -
// a third machine appearing with a key already reported on two is news -
// without re-firing every five minutes on an unchanged one.
async function checkSharedSSHKeys(): Promise<void> {
  const groups = await db
    .selectFrom("ssh_host_keys")
    .innerJoin("hosts", "hosts.id", "ssh_host_keys.host_id")
    .select([
      "ssh_host_keys.fingerprint_sha256 as fingerprint",
      sql<string>`count(distinct hosts.ip)`.as("ip_count"),
      sql<string[]>`array_agg(distinct host(hosts.ip))`.as("ips"),
    ])
    .where("ssh_host_keys.fingerprint_sha256", "!=", "")
    .groupBy("ssh_host_keys.fingerprint_sha256")
    .having(sql<boolean>`count(distinct hosts.ip) > 1`)
    .execute();

  const alerted = await db.selectFrom("ssh_shared_key_alerts").select(["fingerprint_sha256", "ip_count"]).execute();
  const alertedByFingerprint = new Map(alerted.map((a) => [a.fingerprint_sha256, a.ip_count]));

  for (const group of groups) {
    const ipCount = Number(group.ip_count);
    const previous = alertedByFingerprint.get(group.fingerprint);
    if (previous !== undefined && previous >= ipCount) continue;

    const message =
      previous === undefined
        ? `SSH host key ${group.fingerprint} is served by ${ipCount} addresses (${group.ips.join(", ")}) - a cloned image or a shared private key`
        : `SSH host key ${group.fingerprint} is now served by ${ipCount} addresses (was ${previous}): ${group.ips.join(", ")}`;

    await dispatchWebhook("ssh_key.shared", message, {
      fingerprint_sha256: group.fingerprint,
      ip_count: ipCount,
      previous_ip_count: previous ?? null,
      ips: group.ips,
    });

    await db
      .insertInto("ssh_shared_key_alerts")
      .values({ fingerprint_sha256: group.fingerprint, ip_count: ipCount, alerted_at: new Date().toISOString() })
      .onConflict((oc) => oc.column("fingerprint_sha256").doUpdateSet({ ip_count: ipCount, alerted_at: new Date().toISOString() }))
      .execute();
    logger.info({ event: "webhook.ssh_key_shared_alerted", fingerprint_sha256: group.fingerprint, ip_count: ipCount });
  }

  // No longer shared (a host was deleted or retired out of existence, or
  // the key was regenerated) - forget it, so the same fingerprint turning
  // up on two machines again later is reported as new rather than being
  // permanently silenced by a group that no longer exists.
  const stillShared = new Set(groups.map((g) => g.fingerprint));
  const gone = alerted.filter((a) => !stillShared.has(a.fingerprint_sha256));
  if (gone.length > 0) {
    await db
      .deleteFrom("ssh_shared_key_alerts")
      .where(
        "fingerprint_sha256",
        "in",
        gone.map((a) => a.fingerprint_sha256)
      )
      .execute();
  }
}
