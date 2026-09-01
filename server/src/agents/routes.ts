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
import { requestTemplateUpdate } from "../scannerUpdate/requestTemplateUpdate";
import { syncScannerRelease } from "../scannerUpdate/githubSync";
import { SCANNER_TUNABLES, validateOverrides } from "../scannerConfig/tunables";

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

// Manual counterpart to the hourly startGithubSync tick (see
// scannerUpdate/githubSync.ts's syncScannerRelease) - lets an admin see a
// just-published release immediately (e.g. right after tagging one)
// instead of waiting up to an hour. Admin-only, unlike the GET above:
// this makes a real outbound request and a DB write, closer in kind to
// the other admin-triggered actions on this page (request-update) than
// to the read-only release info every viewer already sees.
agentsRouter.post("/latest-release/refresh", requireAdmin, asyncHandler(async (req, res) => {
  try {
    await syncScannerRelease();
  } catch (err) {
    logger.warn({ event: "scanner_release_sync.manual_refresh_failed", err: err instanceof Error ? err.message : String(err) });
    res.status(502).json({ error: err instanceof Error ? err.message : "failed to reach GitHub" });
    return;
  }

  logger.info({ event: "scanner_release_sync.manual_refresh", triggered_by: req.session.username, source_ip: req.ip });
  recordAudit("scanner_release_sync.manual_refresh", req.session.username, req.ip, {});

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
      "scan_slots_running",
      "scan_slots_max",
      "base_config",
      "nuclei_templates_updated_at",
      "template_update_requested_at",
      "template_update_status",
      "template_update_failure_reason",
      "config_overrides",
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

// Dashboard-managed overrides for a subset of this scanner's config.yaml
// (see scannerConfig/tunables.ts for the allowlist and why everything
// else is excluded). Like every other remote action here the webserver
// can't push this - it's stored, and the scanner's own config watcher
// picks it up on its next poll and applies it in memory. The scanner's
// config.yaml on disk is never touched, so a restart falls back to the
// file and the override is simply re-fetched.
//
// An empty object clears every override, which is the "go back to
// config.yaml" action - distinct from sending a partial object, which
// only changes the keys it names.
agentsRouter.put("/:id/config", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scanner agent id" });
    return;
  }
  if (typeof req.body !== "object" || req.body === null || Array.isArray(req.body)) {
    res.status(400).json({ error: "body must be an object of setting -> value" });
    return;
  }

  const validated = validateOverrides(req.body as Record<string, unknown>);
  if (!validated.ok) {
    res.status(400).json({ error: "invalid settings", details: validated.errors });
    return;
  }

  const agent = await db
    .selectFrom("scanner_agents")
    .select(["id", "name"])
    .where("id", "=", req.params.id)
    .where("revoked_at", "is", null)
    .executeTakeFirst();
  if (!agent) {
    res.status(404).json({ error: "scanner agent not found" });
    return;
  }

  const isEmpty = Object.keys(validated.value).length === 0;
  await db
    .updateTable("scanner_agents")
    .set({ config_overrides: isEmpty ? null : JSON.stringify(validated.value) })
    .where("id", "=", req.params.id)
    .execute();

  logger.info({
    event: "scanner.config_updated",
    scanner_agent_id: agent.id,
    scanner_agent_name: agent.name,
    settings: validated.value,
    updated_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("scanner.config_updated", req.session.username, req.ip, {
    scanner_agent_id: agent.id,
    scanner_agent_name: agent.name,
    settings: validated.value,
  });

  res.json({ config_overrides: isEmpty ? null : validated.value });
}));

// The allowlist itself, so the dashboard's form is generated from the
// same definition the server validates against and the two can't drift
// on bounds or labels. Not admin-gated - it's a static description of
// what exists, with no agent's actual values in it.
agentsRouter.get("/config/tunables", asyncHandler(async (_req, res) => {
  res.json(SCANNER_TUNABLES);
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

// Same polled-flag mechanism as request-update above, for the scanner's
// nuclei template tree instead of its binary. This exists because the
// templates are fetched exactly once by install.sh and never refreshed
// afterwards, so the only way to update them used to be an SSH session on
// the scanner host - and specifically one running as the service user,
// since the tree location is per-user (see scanner/CLAUDE.md's installer
// section). 409 if already revoked or a template update is already
// outstanding, re-checked here rather than trusted from the frontend.
agentsRouter.post("/:id/request-template-update", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid scanner agent id" });
    return;
  }

  const outcome = await requestTemplateUpdate(req.params.id as string);
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({
    event: "agent.template_update_requested",
    scanner_agent_id: req.params.id,
    requested_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("agent.template_update_requested", req.session.username, req.ip, { scanner_agent_id: req.params.id });

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
