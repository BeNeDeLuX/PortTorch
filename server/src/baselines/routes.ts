import { Router, type Request } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { recordAudit } from "../audit/log";
import { requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { db } from "../db";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { parseNetwork } from "../subnets/changes";
import { approveBaseline, baselineQuery, baselineWithChanges, listBaselineSummaries } from "./service";

export const baselinesRouter = Router();
baselinesRouter.use(requireAuth);

const uuidSchema = z.string().uuid();

function visibleQuery(req: Request) {
  return baselineQuery(getAllowedScannerAgentIds(req));
}

baselinesRouter.get("/", asyncHandler(async (req, res) => {
  res.json(await listBaselineSummaries(getAllowedScannerAgentIds(req)));
}));

baselinesRouter.get("/:id", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  const found = await baselineWithChanges(req.params.id as string, getAllowedScannerAgentIds(req));
  if (!found) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  res.json(found);
}));

const createSchema = z.object({
  network: z.string().trim().min(1).max(100),
  scannerAgentId: z.string().uuid().nullable().optional(),
  note: z.string().trim().max(500).nullable().optional(),
});

// Approving the current state is an analyst's decision about what is
// expected, so operator-level like triage - not admin-only like excludes,
// which change what gets scanned at all.
//
// A restricted session must name one of its scanners: a baseline over
// every scanner would alert on hosts that session cannot see.
baselinesRouter.post("/", requireOperator, asyncHandler(async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const network = parseNetwork(parsed.data.network);
  if (!network) {
    res.status(400).json({ error: "network must be a CIDR, an address, or a partial IPv4 address such as 10.46" });
    return;
  }
  const scannerAgentId = parsed.data.scannerAgentId ?? null;
  const allowed = getAllowedScannerAgentIds(req);
  if (allowed && (!scannerAgentId || !allowed.includes(scannerAgentId))) {
    res.status(403).json({ error: "choose one of the scanners assigned to your account" });
    return;
  }
  if (scannerAgentId) {
    const agent = await db.selectFrom("scanner_agents").select("id").where("id", "=", scannerAgentId).executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "scanner agent not found" });
      return;
    }
  }

  const existing = await db
    .selectFrom("network_baselines")
    .select("id")
    .where(sql<boolean>`network = network(${network}::inet)`)
    .where((eb) => (scannerAgentId ? eb("scanner_agent_id", "=", scannerAgentId) : eb("scanner_agent_id", "is", null)))
    .executeTakeFirst();
  if (existing) {
    res.status(409).json({ error: "this network already has a baseline - approve its current state instead", id: existing.id });
    return;
  }

  const row = await db
    .insertInto("network_baselines")
    .values({
      network: sql<string>`network(${network}::inet)`,
      scanner_agent_id: scannerAgentId,
      note: parsed.data.note ?? null,
      approved_by: req.session.username ?? null,
    })
    .returning(["id", sql<string>`network::text`.as("network")])
    .executeTakeFirstOrThrow();

  logger.info({ event: "baseline.created", baseline_id: row.id, network: row.network, created_by: req.session.username, source_ip: req.ip });
  recordAudit("baseline.created", req.session.username, req.ip, {
    baseline_id: row.id,
    network: row.network,
    scanner_agent_id: scannerAgentId,
  });
  res.status(201).json(row);
}));

const approveSchema = z.object({ note: z.string().trim().max(500).nullable().optional() });

baselinesRouter.post("/:id/approve", requireOperator, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  const parsed = approveSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const visible = await approveBaseline(req.params.id as string, getAllowedScannerAgentIds(req), req.session.username ?? null, parsed.data.note);
  if (!visible) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  logger.info({ event: "baseline.approved", baseline_id: visible.id, network: visible.network, approved_by: req.session.username, source_ip: req.ip });
  recordAudit("baseline.approved", req.session.username, req.ip, { baseline_id: visible.id, network: visible.network });
  res.status(204).end();
}));

baselinesRouter.delete("/:id", requireOperator, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  const visible = await visibleQuery(req).where("b.id", "=", req.params.id as string).executeTakeFirst();
  if (!visible) {
    res.status(404).json({ error: "baseline not found" });
    return;
  }
  await db.deleteFrom("network_baselines").where("id", "=", visible.id).execute();
  logger.info({ event: "baseline.deleted", baseline_id: visible.id, network: visible.network, deleted_by: req.session.username, source_ip: req.ip });
  recordAudit("baseline.deleted", req.session.username, req.ip, { baseline_id: visible.id, network: visible.network });
  res.status(204).end();
}));
