import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { isIPv4Cidr } from "../lib/net";
import { cidrToRange, coveredFraction, normaliseCidr, parseTargetSpecRanges, type IPv4Range } from "../lib/ipRange";
import { getAppSettings } from "../settings/appSettings";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";

export const networksRouter = Router();
networksRouter.use(requireAuth);

const uuidSchema = z.string().uuid();

// GET is available to everyone who can see scan results - coverage is a
// read-only view of work that already happened. Creating/deleting a
// tracked range is admin-only, matching Excludes: it defines what the
// fleet is measured against, not a day-to-day action.
networksRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  const settings = await getAppSettings();
  const staleDays = settings.networkCoverageStaleDays;
  const windowStart = new Date(Date.now() - staleDays * 24 * 60 * 60 * 1000);

  let networksQuery = db
    .selectFrom("monitored_networks")
    .leftJoin("scanner_agents", "scanner_agents.id", "monitored_networks.scanner_agent_id")
    .select([
      "monitored_networks.id as id",
      "monitored_networks.label as label",
      sql<string>`monitored_networks.cidr::text`.as("cidr"),
      "monitored_networks.scanner_agent_id as scanner_agent_id",
      "scanner_agents.name as scanner_agent_name",
      "monitored_networks.created_by as created_by",
      "monitored_networks.created_at as created_at",
    ]);

  // A scanner-restricted user sees the global ranges (which include their
  // scanner) plus any scoped to a scanner they're allowed to see - never
  // one scoped to a scanner they have no access to at all.
  if (allowed) {
    networksQuery = networksQuery.where((eb) =>
      eb.or([eb("monitored_networks.scanner_agent_id", "is", null), eb("monitored_networks.scanner_agent_id", "in", allowed)])
    );
  }

  const networks = await networksQuery.orderBy("monitored_networks.label").execute();
  if (networks.length === 0) {
    res.json({ staleDays, networks: [] });
    return;
  }

  // Host counts come straight from Postgres's own inet containment
  // (<<= rather than <<, since a /32 tracked range must still contain its
  // one address - << is *strict* containment and would return nothing).
  const hostCountsQuery = db
    .selectFrom("monitored_networks")
    .leftJoin("hosts", (join) =>
      join.on(sql<boolean>`hosts.ip <<= monitored_networks.cidr`).on((eb) =>
        eb.or([
          eb("monitored_networks.scanner_agent_id", "is", null),
          eb(sql`hosts.scanner_agent_id`, "=", sql`monitored_networks.scanner_agent_id`),
        ])
      )
    )
    .select([
      "monitored_networks.id as id",
      sql<string>`count(hosts.id)`.as("host_count"),
      sql<string>`count(hosts.id) filter (where hosts.last_seen_at >= ${windowStart})`.as("recent_host_count"),
    ])
    .groupBy("monitored_networks.id");

  const hostCounts = await hostCountsQuery.execute();
  const countsById = new Map(hostCounts.map((c) => [c.id, c]));

  // Coverage is derived from the scan history rather than stored, so it
  // can't drift. Grouping by target_spec first keeps this small: schedules
  // re-run the same handful of specs over and over, so the number of
  // distinct specs is tiny next to the number of jobs.
  let jobsQuery = db
    .selectFrom("scan_jobs")
    .select([
      "target_spec",
      "scanner_agent_id",
      sql<Date>`max(started_at)`.as("last_started_at"),
      sql<Date>`max(started_at) filter (where started_at >= ${windowStart})`.as("last_started_in_window"),
    ])
    .where("status", "=", "completed")
    .groupBy(["target_spec", "scanner_agent_id"]);
  if (allowed) {
    jobsQuery = jobsQuery.where("scanner_agent_id", "in", allowed);
  }
  const jobs = await jobsQuery.execute();

  const parsedJobs = jobs.map((j) => ({
    scannerAgentId: j.scanner_agent_id,
    lastStartedAt: j.last_started_at,
    inWindow: j.last_started_in_window !== null,
    ranges: parseTargetSpecRanges(j.target_spec),
  }));

  const rows = networks.map((network) => {
    const counts = countsById.get(network.id);
    const range = cidrToRange(network.cidr);

    let lastCoveredAt: Date | null = null;
    let opaqueSpecs = 0;
    const windowRanges: IPv4Range[] = [];

    if (range) {
      for (const job of parsedJobs) {
        if (network.scanner_agent_id && job.scannerAgentId !== network.scanner_agent_id) continue;
        if (job.ranges === null) {
          // A hostname/IPv6 target: it may well have hit this range, but
          // the webserver can't know (the scanner resolves hostnames, see
          // CLAUDE.md's ad-hoc scan section). Counted and surfaced rather
          // than silently treated as "did not cover", so a low coverage
          // figure can be read for what it is.
          opaqueSpecs += 1;
          continue;
        }
        const overlapping = job.ranges.filter((r) => r.start <= range.end && range.start <= r.end);
        if (overlapping.length === 0) continue;
        if (!lastCoveredAt || job.lastStartedAt > lastCoveredAt) lastCoveredAt = job.lastStartedAt;
        if (job.inWindow) windowRanges.push(...overlapping);
      }
    }

    return {
      ...network,
      address_count: range ? range.end - range.start + 1 : 0,
      host_count: Number(counts?.host_count ?? 0),
      recent_host_count: Number(counts?.recent_host_count ?? 0),
      last_covered_at: lastCoveredAt,
      covered_fraction: range ? coveredFraction(range, windowRanges) : 0,
      opaque_scan_count: opaqueSpecs,
    };
  });

  res.json({ staleDays, networks: rows });
}));

const createNetworkSchema = z.object({
  label: z.string().trim().min(1).max(80),
  cidr: z.string().trim().min(1).max(64),
  scannerAgentId: z.string().uuid().nullish(),
});

networksRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createNetworkSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { label } = parsed.data;
  const scannerAgentId = parsed.data.scannerAgentId ?? null;

  // IPv4 CIDR only. A "start-end" range has no cidr column representation
  // and IPv6 has no meaningful coverage percentage (sweeping a /64 is not
  // a thing anyone does), so both are rejected here rather than accepted
  // and then measured wrongly.
  if (!isIPv4Cidr(parsed.data.cidr)) {
    res.status(400).json({ error: "cidr must be an IPv4 CIDR, e.g. 10.0.0.0/24" });
    return;
  }
  // Normalised before it ever reaches the database: Postgres's cidr type
  // rejects host bits outright, and "10.0.0.37/24" is a form masscan and
  // nmap both accept, so operators do type it. See normaliseCidr.
  const cidr = normaliseCidr(parsed.data.cidr);
  if (!cidr) {
    res.status(400).json({ error: "cidr must be an IPv4 CIDR, e.g. 10.0.0.0/24" });
    return;
  }

  let scannerAgentName: string | null = null;
  if (scannerAgentId) {
    const agent = await db
      .selectFrom("scanner_agents")
      .select(["id", "name"])
      .where("id", "=", scannerAgentId)
      .executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scanner agent not found" });
      return;
    }
    scannerAgentName = agent.name;
  }

  // Same NULL-safe application-level duplicate check as excludes: the two
  // partial unique indexes can't both be targeted by one onConflict.
  // Runs against the normalised value, so 10.0.0.37/24 is correctly caught
  // as a duplicate of an existing 10.0.0.0/24.
  const existing = await db
    .selectFrom("monitored_networks")
    .select(["id"])
    .where(sql<boolean>`cidr = ${cidr}::cidr`)
    .where((eb) =>
      scannerAgentId ? eb("scanner_agent_id", "=", scannerAgentId) : eb("scanner_agent_id", "is", null)
    )
    .executeTakeFirst();
  if (existing) {
    res.status(409).json({ error: "this network is already tracked" });
    return;
  }

  const network = await db
    .insertInto("monitored_networks")
    .values({
      label,
      cidr,
      scanner_agent_id: scannerAgentId,
      created_by: req.session.username!,
    })
    .returning(["id", "label", sql<string>`cidr::text`.as("cidr"), "scanner_agent_id", "created_by", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "monitored_network.created",
    network_id: network.id,
    label,
    cidr: network.cidr,
    scanner_agent_id: scannerAgentId,
    scanner_agent_name: scannerAgentName,
    created_by: req.session.username,
  });
  recordAudit("monitored_network.created", req.session.username, req.ip, {
    network_id: network.id,
    label,
    cidr: network.cidr,
    scanner_agent_id: scannerAgentId,
    scanner_agent_name: scannerAgentName,
  });

  res.status(201).json(network);
}));

networksRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid network id" });
    return;
  }

  const result = await db.deleteFrom("monitored_networks").where("id", "=", req.params.id).executeTakeFirst();
  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "network not found" });
    return;
  }

  logger.info({ event: "monitored_network.deleted", network_id: req.params.id, deleted_by: req.session.username });
  recordAudit("monitored_network.deleted", req.session.username, req.ip, { network_id: req.params.id });

  res.status(204).end();
}));
