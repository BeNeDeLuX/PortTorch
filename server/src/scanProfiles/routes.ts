import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { KNOWN_NSE_SCRIPTS } from "./knownNseScripts";

// Admin-only, like scanner agents/schedules/webhooks/excludes - controls
// what an operator can pick when triggering a scan, not a day-to-day host
// action. Modeled directly on excludes/routes.ts's shape (same
// requireAuth/requireAdmin, zod validation, logger.info + recordAudit on
// every mutation) - the one deviation is a PATCH for editing a profile's
// name/scripts in place, safe here (unlike most other entities) because
// scan_requests/scan_schedules only ever hold a resolved snapshot of a
// profile's scripts, never a live reference - see resolve.ts and the
// scan_profiles migration's own comment.
export const scanProfilesRouter = Router();
scanProfilesRouter.use(requireAuth, requireAdmin);

const uuidSchema = z.string().uuid();

const nseScriptsSchema = z
  .array(z.string())
  .min(1, "select at least one NSE script")
  .max(500)
  .refine((scripts) => scripts.every((s) => KNOWN_NSE_SCRIPTS.has(s)), {
    message: "one or more script names are not recognized",
  });

scanProfilesRouter.get(
  "/",
  asyncHandler(async (_req, res) => {
    const profiles = await db
      .selectFrom("scan_profiles")
      .select(["id", "name", "nse_scripts", "created_by", "created_at", "updated_at"])
      .orderBy("name")
      .execute();
    res.json(profiles);
  })
);

const createScanProfileSchema = z.object({
  name: z.string().trim().min(1).max(100),
  nseScripts: nseScriptsSchema,
});

scanProfilesRouter.post(
  "/",
  asyncHandler(async (req, res) => {
    const parsed = createScanProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { name, nseScripts } = parsed.data;

    const existing = await db.selectFrom("scan_profiles").select(["id"]).where("name", "=", name).executeTakeFirst();
    if (existing) {
      res.status(409).json({ error: "a scan profile with this name already exists" });
      return;
    }

    const profile = await db
      .insertInto("scan_profiles")
      .values({ name, nse_scripts: nseScripts, created_by: req.session.username! })
      .returning(["id", "name", "nse_scripts", "created_by", "created_at", "updated_at"])
      .executeTakeFirstOrThrow();

    logger.info({ event: "scan_profile.created", scan_profile_id: profile.id, name, script_count: nseScripts.length, created_by: req.session.username });
    recordAudit("scan_profile.created", req.session.username, req.ip, { scan_profile_id: profile.id, name });

    res.status(201).json(profile);
  })
);

const updateScanProfileSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  nseScripts: nseScriptsSchema.optional(),
});

scanProfilesRouter.patch(
  "/:id",
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      res.status(400).json({ error: "invalid scan profile id" });
      return;
    }
    const parsed = updateScanProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    if (parsed.data.name === undefined && parsed.data.nseScripts === undefined) {
      res.status(400).json({ error: "nothing to update" });
      return;
    }

    if (parsed.data.name !== undefined) {
      const existing = await db
        .selectFrom("scan_profiles")
        .select(["id"])
        .where("name", "=", parsed.data.name)
        .where("id", "!=", req.params.id)
        .executeTakeFirst();
      if (existing) {
        res.status(409).json({ error: "a scan profile with this name already exists" });
        return;
      }
    }

    const profile = await db
      .updateTable("scan_profiles")
      .set({
        ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
        ...(parsed.data.nseScripts !== undefined ? { nse_scripts: parsed.data.nseScripts } : {}),
        updated_at: new Date().toISOString(),
      })
      .where("id", "=", req.params.id)
      .returning(["id", "name", "nse_scripts", "created_by", "created_at", "updated_at"])
      .executeTakeFirst();
    if (!profile) {
      res.status(404).json({ error: "scan profile not found" });
      return;
    }

    logger.info({ event: "scan_profile.updated", scan_profile_id: profile.id, updated_by: req.session.username });
    recordAudit("scan_profile.updated", req.session.username, req.ip, { scan_profile_id: profile.id });

    res.json(profile);
  })
);

scanProfilesRouter.delete(
  "/:id",
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      res.status(400).json({ error: "invalid scan profile id" });
      return;
    }

    // Safe to hard-delete: scan_requests/scan_schedules only ever hold a
    // resolved snapshot of a profile's scripts (nse_scripts/
    // nse_profile_label), never a live FK - so there is nothing here to
    // orphan (see resolve.ts).
    const result = await db.deleteFrom("scan_profiles").where("id", "=", req.params.id).executeTakeFirst();
    if (result.numDeletedRows === 0n) {
      res.status(404).json({ error: "scan profile not found" });
      return;
    }

    logger.info({ event: "scan_profile.deleted", scan_profile_id: req.params.id, deleted_by: req.session.username });
    recordAudit("scan_profile.deleted", req.session.username, req.ip, { scan_profile_id: req.params.id });

    res.status(204).end();
  })
);
