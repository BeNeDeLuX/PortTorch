import fs from "fs";
import path from "path";
import crypto from "crypto";
import { Router } from "express";
import multer from "multer";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { config } from "../config";
import { apiKeyAuth } from "./apiKeyAuth";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";
import { zIp } from "../lib/zodIp";
import { singleParam } from "../lib/reqParams";
import { deriveServiceTags } from "../lib/serviceTags";
import { recordAudit } from "../audit/log";

export const ingestRouter = Router();
ingestRouter.use(asyncHandler(apiKeyAuth));

const createScanJobSchema = z.object({
  targetSpec: z.string().min(1),
  portSpec: z.string().min(1),
  // True only from the long-running "serve" process (its own REST-
  // triggered ad-hoc scans and queue-triggered ones) - see
  // ScanJobsTable.cancellable for why only those can be stopped.
  cancellable: z.boolean().optional().default(false),
});

ingestRouter.post("/scan-jobs", asyncHandler(async (req, res) => {
  const parsed = createScanJobSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const job = await db
    .insertInto("scan_jobs")
    .values({
      scanner_agent_id: req.scannerAgentId!,
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
      status: "running",
      cancellable: parsed.data.cancellable,
    })
    .returning(["id", "status", "started_at"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "scan.started",
    scan_job_id: job.id,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_spec: parsed.data.targetSpec,
    port_spec: parsed.data.portSpec,
    source_ip: req.ip,
  });

  res.status(201).json(job);
}));

const updateScanJobSchema = z.object({
  status: z.enum(["completed", "failed", "cancelled"]),
});

ingestRouter.patch("/scan-jobs/:id", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }
  const parsed = updateScanJobSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const finishedAt = new Date();
  const updated = await db
    .updateTable("scan_jobs")
    .set({ status: parsed.data.status, finished_at: finishedAt })
    .where("id", "=", req.params.id)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .returning(["started_at", "target_spec", "port_spec"])
    .executeTakeFirst();

  if (!updated) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  // Assets scanned aren't part of the PATCH payload itself - the scanner
  // already streamed every host/port/screenshot it found straight into
  // these tables as the scan ran (see the streaming architecture notes),
  // so counting rows tagged with this scan_job_id here is simpler and more
  // reliable than having the scanner separately tally and report totals
  // itself (which would risk drifting from what actually got persisted,
  // e.g. if a host's submission failed partway through).
  const [hostsAndPorts, screenshotCount, rdpScreenshotCount, tlsCertCount] = await Promise.all([
    db
      .selectFrom("host_port_observations")
      .select(({ fn }) => [
        fn.count<number>("host_id").distinct().as("hosts_scanned"),
        sql<number>`count(*) filter (where state = 'open')`.as("open_ports_found"),
      ])
      .where("scan_job_id", "=", req.params.id)
      .executeTakeFirstOrThrow(),
    db.selectFrom("screenshots").select(({ fn }) => fn.countAll<number>().as("count")).where("scan_job_id", "=", req.params.id).executeTakeFirstOrThrow(),
    db.selectFrom("rdp_screenshots").select(({ fn }) => fn.countAll<number>().as("count")).where("scan_job_id", "=", req.params.id).executeTakeFirstOrThrow(),
    db.selectFrom("tls_certificates").select(({ fn }) => fn.countAll<number>().as("count")).where("scan_job_id", "=", req.params.id).executeTakeFirstOrThrow(),
  ]);

  logger.info({
    event: parsed.data.status === "completed" ? "scan.completed" : parsed.data.status === "cancelled" ? "scan.cancelled" : "scan.failed",
    scan_job_id: req.params.id,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_spec: updated.target_spec,
    port_spec: updated.port_spec,
    duration_ms: finishedAt.getTime() - updated.started_at.getTime(),
    hosts_scanned: Number(hostsAndPorts.hosts_scanned),
    open_ports_found: Number(hostsAndPorts.open_ports_found),
    screenshots: Number(screenshotCount.count),
    rdp_screenshots: Number(rdpScreenshotCount.count),
    tls_certificates: Number(tlsCertCount.count),
    source_ip: req.ip,
  });

  res.status(204).end();
}));

// Polled by "serve" mode's cancel watcher (client.go's CheckCancelRequested)
// alongside the existing scan-requests poll, but scoped to a specific job
// rather than "what's next" - a scan in progress needs to check its own
// cancellation status while StartPolling's main loop is busy blocking on
// that same scan.
ingestRouter.get("/scan-jobs/:id/cancel-requested", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }
  const job = await db
    .selectFrom("scan_jobs")
    .select(["cancel_requested_at"])
    .where("id", "=", req.params.id)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }
  res.json({ cancelRequested: job.cancel_requested_at !== null });
}));

// Polled by "serve" mode's update watcher (scanner/internal/updater) - the
// webserver can never push to a scanner (see CLAUDE.md's "Why two
// separate services"), so self-update starts here. Scoped implicitly to
// the authenticated agent (req.scannerAgentId) - the scanner never needs
// to know its own scanner_agents.id.
ingestRouter.get("/update-requested", asyncHandler(async (req, res) => {
  const agent = await db
    .selectFrom("scanner_agents")
    .select(["update_requested_at"])
    .where("id", "=", req.scannerAgentId!)
    .executeTakeFirstOrThrow();
  res.json({ requested: agent.update_requested_at !== null });
}));

// The cached latest-release row (see scannerUpdate/githubSync.ts) - the
// scanner needs this to know *which* version to actually fetch/verify.
ingestRouter.get("/scanner-release", asyncHandler(async (req, res) => {
  const release = await db
    .selectFrom("scanner_release_cache")
    .select(["latest_version", "latest_tag", "release_url"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  res.json({
    latestVersion: release.latest_version,
    latestTag: release.latest_tag,
    releaseUrl: release.release_url,
  });
}));

const updateOutcomeSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("succeeded") }),
  z.object({ status: z.literal("failed"), reason: z.string().min(1) }),
]);

// A "failed" outcome increments update_attempt_count; after 3 failures the
// request is given up on (cleared, status set to 'failed') rather than
// retried forever - re-triggering requires an explicit admin action
// (POST /api/agents/:id/request-update), same as any other terminal
// failure state elsewhere in this codebase (scan_schedules' 'once' type,
// etc.) not silently auto-retrying past a point.
const MAX_UPDATE_ATTEMPTS = 3;

ingestRouter.patch("/update-outcome", asyncHandler(async (req, res) => {
  const parsed = updateOutcomeSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  if (parsed.data.status === "succeeded") {
    await db
      .updateTable("scanner_agents")
      .set({ update_requested_at: null, update_request_status: null, update_failure_reason: null, update_attempt_count: 0 })
      .where("id", "=", req.scannerAgentId!)
      .execute();
    logger.info({ event: "scanner.update_succeeded", scanner_agent_id: req.scannerAgentId, scanner_agent_name: req.scannerAgentName });
    res.status(204).end();
    return;
  }

  const agent = await db
    .selectFrom("scanner_agents")
    .select(["update_attempt_count"])
    .where("id", "=", req.scannerAgentId!)
    .executeTakeFirstOrThrow();
  const attempts = agent.update_attempt_count + 1;

  if (attempts >= MAX_UPDATE_ATTEMPTS) {
    await db
      .updateTable("scanner_agents")
      .set({
        update_requested_at: null,
        update_request_status: "failed",
        update_failure_reason: parsed.data.reason,
        update_attempt_count: attempts,
      })
      .where("id", "=", req.scannerAgentId!)
      .execute();

    // Ingest-path-triggered, like host.new/port.opened - this is a
    // discrete state transition (pending -> given up) detected right at
    // write time, so unlike scan.stale/scan_queue.backlog below it needs
    // no periodic checker or dedup column of its own: it only ever fires
    // once per exhausted retry cycle, and a fresh one only starts after
    // an admin explicitly re-triggers the update (POST /:id/request-update).
    await dispatchWebhook(
      "scanner.update_failed",
      `Scanner "${req.scannerAgentName}" failed to self-update after ${attempts} attempts: ${parsed.data.reason}`,
      { scanner_agent_id: req.scannerAgentId, scanner_agent_name: req.scannerAgentName, attempts, reason: parsed.data.reason }
    );
  } else {
    await db
      .updateTable("scanner_agents")
      .set({ update_request_status: "pending", update_failure_reason: parsed.data.reason, update_attempt_count: attempts })
      .where("id", "=", req.scannerAgentId!)
      .execute();
  }

  logger.info({
    event: "scanner.update_failed",
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    attempt: attempts,
    reason: parsed.data.reason,
    gave_up: attempts >= MAX_UPDATE_ATTEMPTS,
  });
  res.status(204).end();
}));

const progressLogLineSchema = z.object({
  time: z.string(),
  stage: z.string(),
  message: z.string(),
});

const scanProgressSchema = z.object({
  stage: z.string().min(1),
  stageDetail: z.string().optional(),
  logs: z.array(progressLogLineSchema).max(200),
});

// Pushed periodically (every few seconds) by the scanner itself while a
// scan runs - see CLAUDE.md's "Scan progress" section for why this has to
// be scanner-initiated rather than the webserver polling the scanner (all
// communication is scanner-initiated, the webserver can't dial back into
// a scanner that may be behind NAT/a firewall). recent_logs is replaced
// wholesale on every push rather than appended - the scanner already
// keeps its own capped rolling buffer (maxLogLines) and sends the current
// snapshot of it, so there's no need to also cap/merge server-side.
ingestRouter.patch("/scan-jobs/:id/progress", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }
  const parsed = scanProgressSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", req.params.id)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  await db
    .insertInto("scan_job_progress")
    .values({
      scan_job_id: singleParam(req.params.id),
      current_stage: parsed.data.stage,
      stage_detail: parsed.data.stageDetail ?? null,
      recent_logs: JSON.stringify(parsed.data.logs),
      updated_at: new Date().toISOString(),
    })
    .onConflict((oc) =>
      oc.column("scan_job_id").doUpdateSet({
        current_stage: parsed.data.stage,
        stage_detail: parsed.data.stageDetail ?? null,
        recent_logs: JSON.stringify(parsed.data.logs),
        updated_at: new Date().toISOString(),
      })
    )
    .execute();

  res.status(204).end();
}));

const scanFullLogSchema = z.object({
  // Matches the scanner's own maxFullLogLines ceiling
  // (scanner/internal/progress/tracker.go) - kept in sync by hand, same
  // as the periodic progress push's own .max(200) above matching
  // maxLogLines there.
  logs: z.array(progressLogLineSchema).max(10000),
});

// Uploaded exactly once by the scanner, at scan completion (see
// progress.Tracker.Close) - the complete progress log for this job,
// unlike the periodic push above which only ever carries the last
// maxLogLines lines. Scan History's "Details" popup prefers this over
// scan_job_progress.recent_logs when it's present (GET
// /api/scan-jobs/:id/progress in scanJobs/routes.ts) - see CLAUDE.md's
// "Scan progress" section.
ingestRouter.patch("/scan-jobs/:id/full-log", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan job id" });
    return;
  }
  const parsed = scanFullLogSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", req.params.id)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  await db
    .insertInto("scan_job_full_log")
    .values({
      scan_job_id: singleParam(req.params.id),
      logs: JSON.stringify(parsed.data.logs),
    })
    .onConflict((oc) =>
      oc.column("scan_job_id").doUpdateSet({
        logs: JSON.stringify(parsed.data.logs),
        created_at: new Date().toISOString(),
      })
    )
    .execute();

  res.status(204).end();
}));

const sshHostKeySchema = z.object({
  keyType: z.string().min(1),
  bits: z.number().int().positive().optional(),
  fingerprintMd5: z.string().optional(),
  fingerprintSha256: z.string().min(1),
});

const portObservationSchema = z.object({
  port: z.number().int().min(1).max(65535),
  protocol: z.string().default("tcp"),
  state: z.string().default("open"),
  serviceName: z.string().optional(),
  serviceProduct: z.string().optional(),
  serviceVersion: z.string().optional(),
  extraInfo: z.string().optional(),
  osType: z.string().optional(),
  cpes: z.array(z.string()).optional(),
  banner: z.string().optional(),
  sshHostKeys: z.array(sshHostKeySchema).optional(),
  ftpAnonListing: z.string().optional(),
  smbShares: z.string().optional(),
  extraScripts: z.array(z.object({ id: z.string().min(1), output: z.string() })).optional(),
});

const nucleiFindingSchema = z.object({
  port: z.number().int().min(1).max(65535),
  templateId: z.string().min(1),
  name: z.string().min(1),
  severity: z.string().min(1),
  matchedAt: z.string().min(1),
  description: z.string().optional(),
  reference: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  curlCommand: z.string().optional(),
});

const ingestHostsSchema = z.object({
  scanJobId: z.string().uuid(),
  hosts: z.array(
    z.object({
      ip: zIp(),
      hostname: z.string().optional(),
      osName: z.string().optional(),
      osFamily: z.string().optional(),
      osVendor: z.string().optional(),
      deviceType: z.string().optional(),
      osAccuracy: z.number().int().optional(),
      macAddress: z.string().optional(),
      macVendor: z.string().optional(),
      ports: z.array(portObservationSchema),
      nucleiFindings: z.array(nucleiFindingSchema).optional(),
    })
  ),
});

ingestRouter.post("/hosts", asyncHandler(async (req, res) => {
  const parsed = ingestHostsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", parsed.data.scanJobId)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  // Collected during the transaction, dispatched only after it commits -
  // an event for a host/port that ends up rolled back would be a false
  // alert. Port-open events are skipped for hosts that are new in this
  // same ingest (the single host.new notification already covers it;
  // otherwise a brand-new host with 10 open ports would fire 11 webhooks).
  const hostNewEvents: Array<{ ip: string; hostname: string | null }> = [];
  const portOpenedEvents: Array<{ ip: string; hostname: string | null; port: number; serviceName: string | null }> = [];
  const nucleiFindingEvents: Array<{ ip: string; hostname: string | null; templateId: string; name: string; severity: string }> = [];
  const autoTagEvents: Array<{ hostId: string; ip: string; tag: string }> = [];

  await db.transaction().execute(async (trx) => {
    for (const host of parsed.data.hosts) {
      const existingOpenPorts = await trx
        .selectFrom("current_host_ports")
        .innerJoin("hosts", "hosts.id", "current_host_ports.host_id")
        .select(["current_host_ports.port as port"])
        .where("hosts.ip", "=", host.ip)
        .where("hosts.scanner_agent_id", "=", req.scannerAgentId!)
        .where("current_host_ports.state", "=", "open")
        .execute();
      const existingOpenPortSet = new Set(existingOpenPorts.map((p) => p.port));

      const upserted = await trx
        .insertInto("hosts")
        .values({
          ip: host.ip,
          scanner_agent_id: req.scannerAgentId!,
          hostname: host.hostname ?? null,
          os_name: host.osName ?? null,
          os_family: host.osFamily ?? null,
          os_vendor: host.osVendor ?? null,
          device_type: host.deviceType ?? null,
          os_accuracy: host.osAccuracy ?? null,
          mac_address: host.macAddress ?? null,
          mac_vendor: host.macVendor ?? null,
        })
        .onConflict((oc) =>
          oc.columns(["ip", "scanner_agent_id"]).doUpdateSet({
            hostname: host.hostname ?? null,
            last_seen_at: new Date().toISOString(),
            // OS/device classification isn't run on every scan (e.g. -O
            // is root-only, see nmap.go) - only overwrite it when this
            // scan actually produced a match, so a scan without -O
            // doesn't erase a prior good classification.
            os_name: sql`coalesce(excluded.os_name, hosts.os_name)`,
            os_family: sql`coalesce(excluded.os_family, hosts.os_family)`,
            os_vendor: sql`coalesce(excluded.os_vendor, hosts.os_vendor)`,
            device_type: sql`coalesce(excluded.device_type, hosts.device_type)`,
            os_accuracy: sql`coalesce(excluded.os_accuracy, hosts.os_accuracy)`,
            // Same reasoning as OS classification above: MAC is only ever
            // resolved when the target is on the scanner's own local L2
            // segment, so a rescan from a different vantage point (or a
            // routed target) shouldn't erase a MAC already captured.
            mac_address: sql`coalesce(excluded.mac_address, hosts.mac_address)`,
            mac_vendor: sql`coalesce(excluded.mac_vendor, hosts.mac_vendor)`,
          })
        )
        // xmax = 0 is a well-known Postgres idiom for telling an insert
        // and an ON CONFLICT-triggered update apart in the same statement.
        .returning(["id", sql<boolean>`(xmax = 0)`.as("inserted")])
        .executeTakeFirstOrThrow();

      if (upserted.inserted) {
        hostNewEvents.push({ ip: host.ip, hostname: host.hostname ?? null });
      } else {
        for (const p of host.ports) {
          if (p.state === "open" && !existingOpenPortSet.has(p.port)) {
            portOpenedEvents.push({ ip: host.ip, hostname: host.hostname ?? null, port: p.port, serviceName: p.serviceName ?? null });
          }
        }
      }

      if (host.ports.length > 0) {
        await trx
          .insertInto("host_port_observations")
          .values(
            host.ports.map((p) => ({
              host_id: upserted.id,
              scan_job_id: parsed.data.scanJobId,
              port: p.port,
              protocol: p.protocol,
              state: p.state,
              service_name: p.serviceName ?? null,
              service_product: p.serviceProduct ?? null,
              service_version: p.serviceVersion ?? null,
              extra_info: p.extraInfo ?? null,
              os_type: p.osType ?? null,
              cpes: p.cpes ?? null,
              banner: p.banner ?? null,
              ftp_anon_listing: p.ftpAnonListing ?? null,
              smb_shares: p.smbShares ?? null,
              nse_extra: p.extraScripts && p.extraScripts.length > 0 ? JSON.stringify(p.extraScripts) : null,
            }))
          )
          .execute();
      }

      // Auto-tags derived from which services this scan found open -
      // never removed automatically (host_tags has no manual/auto
      // distinction, and a host that stops running a service still once
      // did, which stays worth surfacing) - a user can always delete one
      // by hand, and it simply comes back on a later scan that still
      // finds the same service, same idempotent onConflict-doNothing
      // shape as every other insert in this transaction.
      const derivedTags = deriveServiceTags(host.ports);
      if (derivedTags.length > 0) {
        const insertedTags = await trx
          .insertInto("host_tags")
          .values(derivedTags.map((tag) => ({ host_id: upserted.id, tag })))
          .onConflict((oc) => oc.columns(["host_id", "tag"]).doNothing())
          .returning(["tag"])
          .execute();
        for (const t of insertedTags) {
          autoTagEvents.push({ hostId: upserted.id, ip: host.ip, tag: t.tag });
        }
      }

      const sshHostKeyRows = host.ports.flatMap((p) =>
        (p.sshHostKeys ?? []).map((k) => ({
          host_id: upserted.id,
          scan_job_id: parsed.data.scanJobId,
          port: p.port,
          key_type: k.keyType,
          bits: k.bits ?? null,
          fingerprint_md5: k.fingerprintMd5 ?? null,
          fingerprint_sha256: k.fingerprintSha256,
        }))
      );
      if (sshHostKeyRows.length > 0) {
        await trx.insertInto("ssh_host_keys").values(sshHostKeyRows).execute();
      }

      if ((host.nucleiFindings ?? []).length > 0) {
        // "New" here means "not seen on a prior scan of this exact host" -
        // same host.new/port.opened idiom (only genuinely new matches fire
        // a webhook, a finding that already fired last time stays quiet on
        // a rescan) - keyed on (template_id, matched_at) since the same
        // template can match multiple URLs/paths on the same host.
        const existingFindings = await trx
          .selectFrom("nuclei_findings")
          .select(["template_id", "matched_at"])
          .where("host_id", "=", upserted.id)
          .execute();
        const existingFindingKeys = new Set(existingFindings.map((f) => JSON.stringify([f.template_id, f.matched_at])));

        await trx
          .insertInto("nuclei_findings")
          .values(
            (host.nucleiFindings ?? []).map((f) => ({
              host_id: upserted.id,
              scan_job_id: parsed.data.scanJobId,
              port: f.port,
              template_id: f.templateId,
              name: f.name,
              severity: f.severity,
              matched_at: f.matchedAt,
              description: f.description ?? null,
              reference: f.reference ?? null,
              tags: f.tags ?? null,
              curl_command: f.curlCommand ?? null,
            }))
          )
          .execute();

        for (const f of host.nucleiFindings ?? []) {
          if (!existingFindingKeys.has(JSON.stringify([f.templateId, f.matchedAt]))) {
            nucleiFindingEvents.push({ ip: host.ip, hostname: host.hostname ?? null, templateId: f.templateId, name: f.name, severity: f.severity });
          }
        }
      }

      // Core event for SIEM traceability: which scanner saw which IP on
      // which ports, and when.
      logger.info({
        event: "scan.host_scanned",
        scan_job_id: parsed.data.scanJobId,
        scanner_agent_id: req.scannerAgentId,
        scanner_agent_name: req.scannerAgentName,
        target_ip: host.ip,
        hostname: host.hostname ?? null,
        ports: host.ports.map((p) => ({
          port: p.port,
          protocol: p.protocol,
          state: p.state,
          service_name: p.serviceName ?? null,
          ssh_host_keys: p.sshHostKeys?.length ?? 0,
        })),
        nuclei_findings: host.nucleiFindings?.length ?? 0,
        source_ip: req.ip,
      });
    }
  });

  for (const e of hostNewEvents) {
    dispatchWebhook("host.new", `New host discovered: ${e.hostname || e.ip}`, { ip: e.ip, hostname: e.hostname });
  }
  for (const e of portOpenedEvents) {
    dispatchWebhook(
      "port.opened",
      `Port ${e.port}${e.serviceName ? `/${e.serviceName}` : ""} newly open on ${e.hostname || e.ip}`,
      { ip: e.ip, hostname: e.hostname, port: e.port, service_name: e.serviceName }
    );
  }
  for (const e of nucleiFindingEvents) {
    dispatchWebhook(
      "nuclei.finding",
      `${e.severity} nuclei finding "${e.name}" on ${e.hostname || e.ip}`,
      { ip: e.ip, hostname: e.hostname, template_id: e.templateId, name: e.name, severity: e.severity }
    );
  }
  for (const e of autoTagEvents) {
    logger.info({ event: "host.tag_added", host_id: e.hostId, tag: e.tag, added_by: "auto-tag" });
    recordAudit("host.tag_added", "auto-tag", undefined, { host_id: e.hostId, tag: e.tag, ip: e.ip });
  }

  res.status(204).end();
}));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

const screenshotFieldsSchema = z.object({
  scanJobId: z.string().uuid(),
  hostIp: zIp(),
  port: z.coerce.number().int().min(1).max(65535),
  url: z.string().min(1),
  httpStatus: z.coerce.number().int().optional(),
  pageTitle: z.string().optional(),
  tlsProtocol: z.string().optional(),
  tlsCipher: z.string().optional(),
  tlsSubject: z.string().optional(),
  tlsIssuer: z.string().optional(),
  tlsValidFrom: z.string().datetime({ offset: true }).optional(),
  tlsValidTo: z.string().datetime({ offset: true }).optional(),
  technologies: z.string().optional(),
  headers: z.string().optional(),
  ocrText: z.string().optional(),
});

// Headers arrive as a JSON-encoded string form field (multipart/form-data
// has no native object type). Malformed input is dropped rather than
// rejecting the whole screenshot - headers are supplementary, not
// load-bearing.
function parseHeadersField(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" && !Array.isArray(obj) ? JSON.stringify(obj) : null;
  } catch {
    return null;
  }
}

ingestRouter.post("/screenshots", upload.single("image"), asyncHandler(async (req, res) => {
  const parsed = screenshotFieldsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  if (!req.file) {
    res.status(400).json({ error: "image file is required" });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", parsed.data.scanJobId)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  const host = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", parsed.data.hostIp)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!host) {
    res.status(404).json({ error: "host not found, ingest port observations first" });
    return;
  }

  fs.mkdirSync(config.screenshotDir, { recursive: true });
  const filename = `${crypto.randomUUID()}.png`;
  const imagePath = path.join(config.screenshotDir, filename);
  fs.writeFileSync(imagePath, req.file.buffer);

  const technologies = parsed.data.technologies
    ? parsed.data.technologies.split(",").map((t) => t.trim()).filter(Boolean)
    : null;

  const row = await db
    .insertInto("screenshots")
    .values({
      host_id: host.id,
      scan_job_id: parsed.data.scanJobId,
      port: parsed.data.port,
      url: parsed.data.url,
      image_path: imagePath,
      http_status: parsed.data.httpStatus ?? null,
      page_title: parsed.data.pageTitle ?? null,
      tls_protocol: parsed.data.tlsProtocol ?? null,
      tls_cipher: parsed.data.tlsCipher ?? null,
      tls_subject: parsed.data.tlsSubject ?? null,
      tls_issuer: parsed.data.tlsIssuer ?? null,
      tls_valid_from: parsed.data.tlsValidFrom ? new Date(parsed.data.tlsValidFrom) : null,
      tls_valid_to: parsed.data.tlsValidTo ? new Date(parsed.data.tlsValidTo) : null,
      technologies,
      headers: parseHeadersField(parsed.data.headers),
      ocr_text: parsed.data.ocrText || null,
    })
    .returning(["id"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "scan.screenshot_captured",
    kind: "http",
    scan_job_id: parsed.data.scanJobId,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_ip: parsed.data.hostIp,
    port: parsed.data.port,
  });

  res.status(201).json(row);
}));

const rdpScreenshotFieldsSchema = z.object({
  scanJobId: z.string().uuid(),
  hostIp: zIp(),
  port: z.coerce.number().int().min(1).max(65535),
  ocrText: z.string().optional(),
});

ingestRouter.post("/rdp-screenshots", upload.single("image"), asyncHandler(async (req, res) => {
  const parsed = rdpScreenshotFieldsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  if (!req.file) {
    res.status(400).json({ error: "image file is required" });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", parsed.data.scanJobId)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  const host = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", parsed.data.hostIp)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!host) {
    res.status(404).json({ error: "host not found, ingest port observations first" });
    return;
  }

  fs.mkdirSync(config.screenshotDir, { recursive: true });
  const filename = `${crypto.randomUUID()}.png`;
  const imagePath = path.join(config.screenshotDir, filename);
  fs.writeFileSync(imagePath, req.file.buffer);

  const row = await db
    .insertInto("rdp_screenshots")
    .values({
      host_id: host.id,
      scan_job_id: parsed.data.scanJobId,
      port: parsed.data.port,
      image_path: imagePath,
      ocr_text: parsed.data.ocrText || null,
    })
    .returning(["id"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "scan.screenshot_captured",
    kind: "rdp",
    scan_job_id: parsed.data.scanJobId,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_ip: parsed.data.hostIp,
    port: parsed.data.port,
  });

  res.status(201).json(row);
}));

// Scan request queue: scanners poll this for pending jobs (created by the
// rescan button or schedules) instead of requiring the webserver to
// actively open connections into their network segment.
ingestRouter.get("/scan-requests/next", asyncHandler(async (req, res) => {
  const claimed = await sql<{
    id: string;
    target_spec: string;
    port_spec: string;
    nse_profile: string;
    nse_scripts: string[] | null;
    nuclei_profile: string;
    nuclei_tags: string[] | null;
  }>`
    UPDATE scan_requests
    SET status = 'claimed', claimed_at = now()
    WHERE id = (
      SELECT id FROM scan_requests
      WHERE scanner_agent_id = ${req.scannerAgentId!} AND status = 'pending'
      ORDER BY created_at
      FOR UPDATE SKIP LOCKED
      LIMIT 1
    )
    RETURNING id, target_spec, port_spec, nse_profile, nse_scripts, nuclei_profile, nuclei_tags
  `.execute(db);

  const next = claimed.rows[0];
  if (!next) {
    res.status(204).end();
    return;
  }

  logger.info({
    event: "scan_request.claimed",
    scan_request_id: next.id,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_spec: next.target_spec,
    port_spec: next.port_spec,
  });

  // nse_profile_label/nuclei_profile_label are display-only and never
  // needed by the scanner - not included here.
  res.json({
    id: next.id,
    targetSpec: next.target_spec,
    portSpec: next.port_spec,
    nseProfile: next.nse_profile,
    nseScripts: next.nse_scripts,
    nucleiProfile: next.nuclei_profile,
    nucleiTags: next.nuclei_tags,
  });
}));

const completeScanRequestSchema = z.object({
  scanJobId: z.string().uuid(),
  status: z.enum(["completed", "failed", "cancelled"]),
});

ingestRouter.patch("/scan-requests/:id", asyncHandler(async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scan request id" });
    return;
  }
  const parsed = completeScanRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const result = await db
    .updateTable("scan_requests")
    .set({
      status: parsed.data.status,
      scan_job_id: parsed.data.scanJobId,
      completed_at: new Date().toISOString(),
    })
    .where("id", "=", req.params.id)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    res.status(404).json({ error: "scan request not found" });
    return;
  }

  logger.info({
    event: parsed.data.status === "completed" ? "scan_request.completed" : "scan_request.failed",
    scan_request_id: req.params.id,
    scan_job_id: parsed.data.scanJobId,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
  });

  res.status(204).end();
}));

const tlsCertificateFieldsSchema = z.object({
  scanJobId: z.string().uuid(),
  hostIp: zIp(),
  port: z.number().int().min(1).max(65535),
  subjectCn: z.string().optional(),
  issuerCn: z.string().optional(),
  sanList: z.array(z.string()).optional(),
  notBefore: z.string().datetime({ offset: true }).optional(),
  notAfter: z.string().datetime({ offset: true }).optional(),
  fingerprintSha256: z.string().min(1),
  signatureAlgorithm: z.string().optional(),
  selfSigned: z.boolean().default(false),
  tlsVersion: z.string().optional(),
  cipherSuite: z.string().optional(),
  keyAlgorithm: z.string().optional(),
  keyBits: z.number().int().optional(),
});

ingestRouter.post("/tls-certificates", asyncHandler(async (req, res) => {
  const parsed = tlsCertificateFieldsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const job = await db
    .selectFrom("scan_jobs")
    .select(["id"])
    .where("id", "=", parsed.data.scanJobId)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!job) {
    res.status(404).json({ error: "scan job not found" });
    return;
  }

  const host = await db
    .selectFrom("hosts")
    .select(["id"])
    .where("ip", "=", parsed.data.hostIp)
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .executeTakeFirst();
  if (!host) {
    res.status(404).json({ error: "host not found, ingest port observations first" });
    return;
  }

  const row = await db
    .insertInto("tls_certificates")
    .values({
      host_id: host.id,
      scan_job_id: parsed.data.scanJobId,
      port: parsed.data.port,
      subject_cn: parsed.data.subjectCn ?? null,
      issuer_cn: parsed.data.issuerCn ?? null,
      san_list: parsed.data.sanList ?? null,
      not_before: parsed.data.notBefore ? new Date(parsed.data.notBefore) : null,
      not_after: parsed.data.notAfter ? new Date(parsed.data.notAfter) : null,
      fingerprint_sha256: parsed.data.fingerprintSha256,
      signature_algorithm: parsed.data.signatureAlgorithm ?? null,
      self_signed: parsed.data.selfSigned,
      tls_version: parsed.data.tlsVersion ?? null,
      cipher_suite: parsed.data.cipherSuite ?? null,
      key_algorithm: parsed.data.keyAlgorithm ?? null,
      key_bits: parsed.data.keyBits ?? null,
    })
    .returning(["id"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "scan.tls_certificate_captured",
    scan_job_id: parsed.data.scanJobId,
    scanner_agent_id: req.scannerAgentId,
    scanner_agent_name: req.scannerAgentName,
    target_ip: parsed.data.hostIp,
    port: parsed.data.port,
    subject_cn: parsed.data.subjectCn ?? null,
    fingerprint_sha256: parsed.data.fingerprintSha256,
    self_signed: parsed.data.selfSigned,
  });

  res.status(201).json(row);
}));

// The central exclude list (managed via the dashboard's admin-only
// Excludes page) - fetched fresh by every scanner before every scan
// (scan/menu/serve, not just webserver-triggered ones). Each scanner gets
// the inherited defaults (scanner_agent_id IS NULL) plus anything scoped
// specifically to it - private IP ranges commonly overlap across scanners
// sitting in different networks, so an exclude meant for one scanner's
// network must not silently also apply to another's.
ingestRouter.get("/excludes", asyncHandler(async (req, res) => {
  const excludes = await db
    .selectFrom("scan_excludes")
    .select(["kind", "value"])
    .where((eb) => eb.or([eb("scanner_agent_id", "is", null), eb("scanner_agent_id", "=", req.scannerAgentId!)]))
    .execute();
  res.json({
    ips: excludes.filter((e) => e.kind === "ip").map((e) => e.value),
    ports: excludes.filter((e) => e.kind === "port").map((e) => e.value),
    // "ip_port" values are stored as "ip:portSpec" for IPv4, or
    // "[ipv6]:portSpec" for IPv6 (validated at creation time in
    // excludes/routes.ts's isValidIPPortValue - bracket notation is
    // required there specifically because an IPv6 address itself contains
    // colons, so a plain first-colon split can't tell address from port
    // unambiguously) - split back into the shape the scanner expects
    // (pipeline.IPPortExclude via client.go's GetExcludes), which just
    // wants clean, already-split ip/portSpec strings regardless of family.
    ipPorts: excludes
      .filter((e) => e.kind === "ip_port")
      .map((e) => {
        if (e.value.startsWith("[")) {
          const closeIdx = e.value.indexOf("]:");
          return { ip: e.value.slice(1, closeIdx), portSpec: e.value.slice(closeIdx + 2) };
        }
        const idx = e.value.indexOf(":");
        return { ip: e.value.slice(0, idx), portSpec: e.value.slice(idx + 1) };
      }),
  });
}));

// Manual per-host SNI/screenshot-URL overrides (see CLAUDE.md's "Manual
// probe hostname override" section) - unlike excludes, there's no global
// variant: a host's identity is (ip, scanner_agent_id), so this is scoped
// strictly to the requesting scanner's own hosts (`=`, not excludes'
// global-OR-scoped union), or an override meant for one scanner's device
// could leak onto a different scanner's same-IP device on another network.
ingestRouter.get("/probe-hostnames", asyncHandler(async (req, res) => {
  const rows = await db
    .selectFrom("hosts")
    .select(["ip", "probe_hostname"])
    .where("scanner_agent_id", "=", req.scannerAgentId!)
    .where("probe_hostname", "is not", null)
    .execute();
  res.json(rows.map((r) => ({ ip: r.ip, hostname: r.probe_hostname })));
}));
