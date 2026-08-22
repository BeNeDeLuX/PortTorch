import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { config } from "../config";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { parseBearerToken } from "../ingest/apiKeyAuth";
import { VERSION } from "../version";

export const observabilityRouter = Router();

const startedAt = Date.now();

// Liveness/readiness for a load balancer or container orchestrator.
// Unauthenticated on purpose - it exposes no fleet data, only whether
// this process can reach its database, and a health check that needs a
// credential is one most infrastructure can't actually use. Returns 503
// rather than throwing so the caller sees a clear "not ready" instead of
// a generic error page.
observabilityRouter.get("/healthz", asyncHandler(async (_req, res) => {
  try {
    await sql`SELECT 1`.execute(db);
  } catch (err) {
    logger.warn({ event: "healthz.db_unreachable", err: err instanceof Error ? err.message : String(err) });
    res.status(503).json({ status: "degraded", database: "unreachable", version: VERSION });
    return;
  }
  res.json({ status: "ok", database: "ok", version: VERSION, uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000) });
}));

function metric(name: string, help: string, type: "gauge" | "counter", value: number, labels = ""): string {
  return metricFamily(name, help, type, [{ labels, value }]);
}

// One HELP/TYPE header followed by every labelled sample. Prometheus
// rejects a metric name whose HELP/TYPE is declared more than once, so a
// multi-series metric cannot just be two metric() calls - which is
// exactly what porttorch_table_bytes would have been.
function metricFamily(
  name: string,
  help: string,
  type: "gauge" | "counter",
  samples: Array<{ labels?: string; value: number }>
): string {
  const header = `# HELP ${name} ${help}\n# TYPE ${name} ${type}\n`;
  return header + samples.map((s) => `${name}${s.labels ?? ""} ${s.value}\n`).join("");
}

// Prometheus exposition, hand-written rather than pulling in
// prometheus/client_golang's Node equivalent - the same call the scanner's
// own internal/api/metrics.go makes, and for the same reason: a handful of
// gauges doesn't justify a registry/encoding dependency.
//
// The scanner has exposed /metrics all along while the webserver - the
// component holding every bit of state and running a dozen background
// tickers - exposed nothing, so the half of the system most worth
// monitoring was the half you couldn't.
//
// Unlike /healthz this does reveal fleet shape (host counts, scanner
// counts, queue depths), so it's **disabled entirely unless
// METRICS_TOKEN is configured** and requires that token as a bearer.
// Fail-closed rather than defaulting to open: an operator who never
// thought about this endpoint doesn't silently publish their fleet size.
// A dedicated token rather than reusing the External API's own
// (apiTokens): a scrape every 15s would churn last_used_at and eat that
// token's rate-limit budget, and monitoring infrastructure typically
// can't rotate an app-managed credential anyway.
observabilityRouter.get("/metrics", asyncHandler(async (req, res) => {
  if (!config.metricsToken) {
    res.status(404).json({ error: "metrics endpoint is disabled (set METRICS_TOKEN to enable it)" });
    return;
  }
  if (parseBearerToken(req.header("authorization") ?? "") !== config.metricsToken) {
    res.status(401).json({ error: "invalid metrics token" });
    return;
  }

  // One round trip rather than a dozen - a scrape runs on a short
  // interval, so this is the query shape that actually matters here.
  const row = await sql<{
    hosts: string;
    agents: string;
    agents_revoked: string;
    scans_running: string;
    requests_pending: string;
    retry_backlog: string;
    submit_queue_pending: string;
    triaged_findings: string;
    port_observations: string;
    nuclei_findings: string;
    screenshots: string;
    port_observations_bytes: string;
    nuclei_findings_bytes: string;
    database_bytes: string;
  }>`
    SELECT
      (SELECT count(*) FROM hosts) AS hosts,
      (SELECT count(*) FROM scanner_agents WHERE revoked_at IS NULL) AS agents,
      (SELECT count(*) FROM scanner_agents WHERE revoked_at IS NOT NULL) AS agents_revoked,
      (SELECT count(*) FROM scan_jobs WHERE status = 'running') AS scans_running,
      (SELECT count(*) FROM scan_requests WHERE status = 'pending') AS requests_pending,
      (SELECT count(*) FROM webhook_retry_queue) AS retry_backlog,
      (SELECT coalesce(sum(submit_queue_pending), 0) FROM scanner_agents WHERE revoked_at IS NULL) AS submit_queue_pending,
      (SELECT count(*) FROM finding_triage) AS triaged_findings,
      (SELECT count(*) FROM host_port_observations) AS port_observations,
      (SELECT count(*) FROM nuclei_findings) AS nuclei_findings,
      (SELECT count(*) FROM screenshots) + (SELECT count(*) FROM rdp_screenshots) AS screenshots,
      -- pg_total_relation_size is a catalog lookup, not a scan, so this
      -- stays cheap enough for a 15s scrape. These are the append-only
      -- tables that grow with every scan and are only ever reclaimed when
      -- their host is - the ones worth watching before they become a
      -- problem rather than after.
      pg_total_relation_size('host_port_observations') AS port_observations_bytes,
      pg_total_relation_size('nuclei_findings') AS nuclei_findings_bytes,
      pg_database_size(current_database()) AS database_bytes
  `.execute(db);

  const r = row.rows[0];
  // Every count() is a Postgres bigint, which node-postgres hands back as
  // a string - the same trap that has produced real bugs here three times
  // now, and one that would silently emit invalid exposition text.
  const n = (v: string) => Number(v);

  const body =
    metric("porttorch_build_info", "Webserver build information", "gauge", 1, `{version="${VERSION}"}`) +
    metric("porttorch_uptime_seconds", "Seconds since this webserver process started", "gauge", Math.floor((Date.now() - startedAt) / 1000)) +
    metric("porttorch_hosts_total", "Hosts currently in the database", "gauge", n(r.hosts)) +
    metric("porttorch_scanner_agents", "Scanner agents that can still authenticate", "gauge", n(r.agents)) +
    metric("porttorch_scanner_agents_revoked", "Scanner agents that have been revoked", "gauge", n(r.agents_revoked)) +
    metric("porttorch_scans_running", "Scan jobs currently reported as running", "gauge", n(r.scans_running)) +
    metric("porttorch_scan_requests_pending", "Queued scan requests not yet claimed by a scanner", "gauge", n(r.requests_pending)) +
    metric("porttorch_webhook_retry_backlog", "Alert deliveries waiting to be retried", "gauge", n(r.retry_backlog)) +
    metric("porttorch_submit_queue_pending", "Host submissions queued for retry across all scanners", "gauge", n(r.submit_queue_pending)) +
    metric("porttorch_triaged_findings", "Findings with an explicit triage decision", "gauge", n(r.triaged_findings)) +
    metric("porttorch_port_observations_total", "Rows in host_port_observations (append-only, one per port per scan)", "gauge", n(r.port_observations)) +
    metric("porttorch_nuclei_findings_total", "Rows in nuclei_findings (append-only, one per match per scan)", "gauge", n(r.nuclei_findings)) +
    metric("porttorch_screenshots_total", "Stored screenshots across both capture types", "gauge", n(r.screenshots)) +
    metricFamily("porttorch_table_bytes", "Total on-disk size including indexes", "gauge", [
      { labels: '{table="host_port_observations"}', value: n(r.port_observations_bytes) },
      { labels: '{table="nuclei_findings"}', value: n(r.nuclei_findings_bytes) },
    ]) +
    metric("porttorch_database_bytes", "Total size of the PortTorch database", "gauge", n(r.database_bytes));

  res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
  res.send(body);
}));
