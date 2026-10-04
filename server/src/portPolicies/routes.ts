import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { recordAudit } from "../audit/log";
import { requireAdmin, requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { db } from "../db";
import { asyncHandler } from "../lib/asyncHandler";
import { parsePortSpec } from "../lib/portSpec";
import { logger } from "../logger";
import { parseNetwork } from "../subnets/changes";
import { listPolicySummaries, policyWithViolations } from "./service";

export const portPoliciesRouter = Router();
portPoliciesRouter.use(requireAuth);

const uuidSchema = z.string().uuid();

// Every role can see the policies and what violates them - knowing a
// finding exists is no more sensitive than the finding. Writing one is
// admin-only: a policy is configuration that decides what alerts, like an
// exclude decides what is scanned, not an analyst's day-to-day call.
portPoliciesRouter.get("/", asyncHandler(async (req, res) => {
  res.json(await listPolicySummaries(getAllowedScannerAgentIds(req)));
}));

portPoliciesRouter.get("/:id", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  const found = await policyWithViolations(req.params.id as string, getAllowedScannerAgentIds(req));
  if (!found) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  res.json(found);
}));

const fields = {
  name: z.string().trim().min(1).max(100),
  network: z.string().trim().min(1).max(100),
  scannerAgentId: z.string().uuid().nullable().optional(),
  mode: z.enum(["allow", "deny"]),
  ports: z.string().trim().min(1).max(2000),
  note: z.string().trim().max(500).nullable().optional(),
  enabled: z.boolean().optional(),
};
const createSchema = z.object(fields);
const updateSchema = z.object(fields).partial();

// Both checks a save needs, so a typo is refused with its reason rather
// than producing a policy that silently matches nothing.
async function validate(network: string | undefined, ports: string | undefined, scannerAgentId: string | null | undefined) {
  if (network !== undefined && !parseNetwork(network)) return "network must be a CIDR, an address, or a partial IPv4 address such as 10.46";
  if (ports !== undefined && !parsePortSpec(ports)) return "ports must be a port list such as 22,80,443 or 1-1024,U:53";
  if (scannerAgentId) {
    const agent = await db.selectFrom("scanner_agents").select("id").where("id", "=", scannerAgentId).executeTakeFirst();
    if (!agent) return "scanner agent not found";
  }
  return null;
}

portPoliciesRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const invalid = await validate(parsed.data.network, parsed.data.ports, parsed.data.scannerAgentId);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }
  const row = await db
    .insertInto("port_policies")
    .values({
      name: parsed.data.name,
      network: sql<string>`network(${parseNetwork(parsed.data.network)}::inet)`,
      scanner_agent_id: parsed.data.scannerAgentId ?? null,
      mode: parsed.data.mode,
      ports: parsed.data.ports,
      note: parsed.data.note ?? null,
      enabled: parsed.data.enabled ?? true,
      created_by: req.session.username ?? null,
    })
    .returning(["id", sql<string>`network::text`.as("network")])
    .executeTakeFirstOrThrow();
  logger.info({ event: "port_policy.created", policy_id: row.id, network: row.network, mode: parsed.data.mode, ports: parsed.data.ports, created_by: req.session.username, source_ip: req.ip });
  recordAudit("port_policy.created", req.session.username, req.ip, {
    policy_id: row.id,
    name: parsed.data.name,
    network: row.network,
    mode: parsed.data.mode,
    ports: parsed.data.ports,
  });
  res.status(201).json(row);
}));

portPoliciesRouter.patch("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success || Object.keys(parsed.data).length === 0) {
    res.status(400).json({ error: parsed.success ? "nothing to update" : parsed.error.flatten() });
    return;
  }
  const invalid = await validate(parsed.data.network, parsed.data.ports, parsed.data.scannerAgentId);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }
  const d = parsed.data;
  // A rule that changed is a different rule: what was already reported
  // under the old one says nothing about the new one, so the bookkeeping
  // starts over and the next check reports the current violations.
  const ruleChanged = d.network !== undefined || d.ports !== undefined || d.mode !== undefined || d.scannerAgentId !== undefined;
  const result = await db
    .updateTable("port_policies")
    .set({
      ...(d.name !== undefined ? { name: d.name } : {}),
      ...(d.network !== undefined ? { network: sql<string>`network(${parseNetwork(d.network)}::inet)` } : {}),
      ...(d.scannerAgentId !== undefined ? { scanner_agent_id: d.scannerAgentId } : {}),
      ...(d.mode !== undefined ? { mode: d.mode } : {}),
      ...(d.ports !== undefined ? { ports: d.ports } : {}),
      ...(d.note !== undefined ? { note: d.note } : {}),
      ...(d.enabled !== undefined ? { enabled: d.enabled } : {}),
      ...(ruleChanged ? { alerted_keys: [] } : {}),
      updated_at: new Date(),
    })
    .where("id", "=", req.params.id as string)
    .executeTakeFirst();
  if (result.numUpdatedRows === 0n) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  logger.info({ event: "port_policy.updated", policy_id: req.params.id, changes: Object.keys(d), updated_by: req.session.username, source_ip: req.ip });
  recordAudit("port_policy.updated", req.session.username, req.ip, { policy_id: req.params.id, ...d });
  res.status(204).end();
}));

portPoliciesRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  const row = await db
    .deleteFrom("port_policies")
    .where("id", "=", req.params.id as string)
    .returning(["name", sql<string>`network::text`.as("network")])
    .executeTakeFirst();
  if (!row) {
    res.status(404).json({ error: "policy not found" });
    return;
  }
  logger.info({ event: "port_policy.deleted", policy_id: req.params.id, deleted_by: req.session.username, source_ip: req.ip });
  recordAudit("port_policy.deleted", req.session.username, req.ip, { policy_id: req.params.id, name: row.name, network: row.network });
  res.status(204).end();
}));
