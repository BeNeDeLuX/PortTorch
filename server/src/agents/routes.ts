import crypto from "crypto";
import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { hashApiKey } from "../ingest/apiKeyAuth";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestScannerUpdate } from "../scannerUpdate/requestUpdate";

export const agentsRouter = Router();
agentsRouter.use(requireAuth);

// The cached latest scanner-vX.Y.Z release (see scannerUpdate/githubSync.ts)
// - read-only fleet info, not admin-gated (same access level as the agent
// list itself), so the Scanner Agents page can show every viewer which
// version is current even though only an admin can trigger an update.
agentsRouter.get("/latest-release", asyncHandler(async (req, res) => {
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

agentsRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let query = db
    .selectFrom("scanner_agents")
    .select([
      "id",
      "name",
      "last_seen_at",
      "last_seen_ip",
      "version",
      "created_at",
      "revoked_at",
      "update_requested_at",
      "update_request_status",
      "update_failure_reason",
      "submit_queue_pending",
    ]);
  if (allowed) {
    query = query.where("id", "in", allowed);
  }
  const agents = await query.orderBy("created_at", "desc").execute();
  res.json(agents);
}));

const createAgentSchema = z.object({ name: z.string().min(1) });

agentsRouter.post("/", requireAdmin, asyncHandler(async (req, res) => {
  const parsed = createAgentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const apiKey = crypto.randomBytes(32).toString("hex");
  const agent = await db
    .insertInto("scanner_agents")
    .values({ name: parsed.data.name, api_key_hash: hashApiKey(apiKey) })
    .returning(["id", "name", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({
    event: "agent.created",
    scanner_agent_id: agent.id,
    scanner_agent_name: agent.name,
    created_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("agent.created", req.session.username, req.ip, { scanner_agent_id: agent.id, name: agent.name });

  // The plaintext key is only returned once, at creation time.
  res.status(201).json({ ...agent, apiKey });
}));

const uuidSchema = z.string().uuid();

agentsRouter.post("/:id/revoke", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scanner agent id" });
    return;
  }

  const result = await db
    .updateTable("scanner_agents")
    .set({ revoked_at: new Date() })
    .where("id", "=", req.params.id)
    .where("revoked_at", "is", null)
    .returning(["name"])
    .executeTakeFirst();

  if (!result) {
    res.status(404).json({ error: "scanner agent not found or already revoked" });
    return;
  }

  logger.info({
    event: "agent.revoked",
    scanner_agent_id: req.params.id,
    scanner_agent_name: result.name,
    revoked_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("agent.revoked", req.session.username, req.ip, { scanner_agent_id: req.params.id, name: result.name });

  res.status(204).end();
}));

// Flags the agent for its own update watcher (serve mode only, see
// scanner/internal/updater) to notice on its next poll - the webserver
// can never push to a scanner directly. 409 if already revoked or an
// update is already outstanding (requestScannerUpdate re-checks both,
// not trusted from the frontend's last poll).
agentsRouter.post("/:id/request-update", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scanner agent id" });
    return;
  }

  const outcome = await requestScannerUpdate(req.params.id as string);
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({
    event: "agent.update_requested",
    scanner_agent_id: req.params.id,
    requested_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("agent.update_requested", req.session.username, req.ip, { scanner_agent_id: req.params.id });

  res.status(204).end();
}));

// Only ever allowed on an already-revoked agent - deleting a still-active
// one would immediately break its ability to authenticate without the
// explicit revoke step's own audit trail. scan_jobs/scan_requests keep
// their historical rows with scanner_agent_id set to NULL (see the
// scanner_agent_delete migration) rather than being deleted along with
// the agent; scan_schedules/scan_excludes scoped to it do cascade away,
// since a schedule or an agent-scoped exclude has no meaning once its
// agent is gone.
agentsRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scanner agent id" });
    return;
  }

  const result = await db
    .deleteFrom("scanner_agents")
    .where("id", "=", req.params.id)
    .where("revoked_at", "is not", null)
    .returning(["name"])
    .executeTakeFirst();

  if (!result) {
    res.status(404).json({ error: "scanner agent not found, or not yet revoked" });
    return;
  }

  logger.info({
    event: "agent.deleted",
    scanner_agent_id: req.params.id,
    scanner_agent_name: result.name,
    deleted_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("agent.deleted", req.session.username, req.ip, { scanner_agent_id: req.params.id, name: result.name });

  res.status(204).end();
}));
