import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { computeNetworkCoverage } from "./coverage";
import { isIPv4Cidr } from "../lib/net";
import { normaliseCidr } from "../lib/ipRange";
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
  res.json(await computeNetworkCoverage(getAllowedScannerAgentIds(req) ?? null));
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
