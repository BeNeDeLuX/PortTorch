import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { KNOWN_NUCLEI_SEVERITIES } from "./knownSeverities";

// Admin-only CRUD for named nuclei tag/severity presets, modeled
// structurally on scanProfiles/routes.ts (requireAuth/requireAdmin, zod
// validation, logger.info + recordAudit on every mutation, a PATCH safe
// here for the identical reason it's safe there: scan_requests/
// scan_schedules only ever hold a resolved snapshot of a profile's tags,
// never a live reference - see resolve.ts).
export const nucleiProfilesRouter = Router();
nucleiProfilesRouter.use(requireAuth, requireAdmin);

const uuidSchema = z.string().uuid();

// Tags get structural validation only, NOT an allowlist the way
// KNOWN_NSE_SCRIPTS enforces script names - confirmed by testing that
// nuclei's own tag taxonomy is far too large and fast-moving for that: a
// real count against a freshly downloaded template tree returned 7625
// distinct tags (cve2024, wp-plugin, lfi, intrusive, ...), growing with
// every template release. This is also a fundamentally different risk
// than an unrecognized NSE script name (a hard error that aborts nmap for
// every host in the scan, the http-elasticsearch incident) - an
// unrecognized nuclei tag just means zero templates match, a harmless
// no-op, so there's nothing here worth rejecting beyond basic shape.
const nucleiTagSchema = z.string().trim().toLowerCase().regex(/^[a-z0-9-]{1,50}$/, "tags must be lowercase alphanumeric/hyphen");
const nucleiTagsSchema = z.array(nucleiTagSchema).max(200);

const severitySchema = z.string().refine((s) => KNOWN_NUCLEI_SEVERITIES.has(s), { message: "unrecognized severity" });
const severitiesSchema = z.array(severitySchema).max(KNOWN_NUCLEI_SEVERITIES.size);

nucleiProfilesRouter.get(
  "/",
  asyncHandler(async (_req, res) => {
    const profiles = await db
      .selectFrom("nuclei_profiles")
      .select(["id", "name", "tags", "severities", "excluded_tags", "created_by", "created_at", "updated_at"])
      .orderBy("name")
      .execute();
    res.json(profiles);
  })
);

const createNucleiProfileSchema = z.object({
  name: z.string().trim().min(1).max(100),
  tags: nucleiTagsSchema.default([]),
  severities: severitiesSchema.default([]),
  excludedTags: nucleiTagsSchema.default([]),
});

nucleiProfilesRouter.post(
  "/",
  asyncHandler(async (req, res) => {
    const parsed = createNucleiProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { name, tags, severities, excludedTags } = parsed.data;
    if (tags.length === 0 && severities.length === 0) {
      res.status(400).json({ error: "select at least one tag or severity" });
      return;
    }

    const existing = await db.selectFrom("nuclei_profiles").select(["id"]).where("name", "=", name).executeTakeFirst();
    if (existing) {
      res.status(409).json({ error: "a nuclei profile with this name already exists" });
      return;
    }

    const profile = await db
      .insertInto("nuclei_profiles")
      .values({ name, tags, severities, excluded_tags: excludedTags, created_by: req.session.username! })
      .returning(["id", "name", "tags", "severities", "excluded_tags", "created_by", "created_at", "updated_at"])
      .executeTakeFirstOrThrow();

    logger.info({ event: "nuclei_profile.created", nuclei_profile_id: profile.id, name, tag_count: tags.length, created_by: req.session.username });
    recordAudit("nuclei_profile.created", req.session.username, req.ip, { nuclei_profile_id: profile.id, name });

    res.status(201).json(profile);
  })
);

const updateNucleiProfileSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  tags: nucleiTagsSchema.optional(),
  severities: severitiesSchema.optional(),
  excludedTags: nucleiTagsSchema.optional(),
});

nucleiProfilesRouter.patch(
  "/:id",
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      res.status(400).json({ error: "invalid nuclei profile id" });
      return;
    }
    const parsed = updateNucleiProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    if (
      parsed.data.name === undefined &&
      parsed.data.tags === undefined &&
      parsed.data.severities === undefined &&
      parsed.data.excludedTags === undefined
    ) {
      res.status(400).json({ error: "nothing to update" });
      return;
    }

    if (parsed.data.name !== undefined) {
      const existing = await db
        .selectFrom("nuclei_profiles")
        .select(["id"])
        .where("name", "=", parsed.data.name)
        .where("id", "!=", req.params.id)
        .executeTakeFirst();
      if (existing) {
        res.status(409).json({ error: "a nuclei profile with this name already exists" });
        return;
      }
    }

    const profile = await db
      .updateTable("nuclei_profiles")
      .set({
        ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
        ...(parsed.data.tags !== undefined ? { tags: parsed.data.tags } : {}),
        ...(parsed.data.severities !== undefined ? { severities: parsed.data.severities } : {}),
        ...(parsed.data.excludedTags !== undefined ? { excluded_tags: parsed.data.excludedTags } : {}),
        updated_at: new Date().toISOString(),
      })
      .where("id", "=", req.params.id)
      .returning(["id", "name", "tags", "severities", "excluded_tags", "created_by", "created_at", "updated_at"])
      .executeTakeFirst();
    if (!profile) {
      res.status(404).json({ error: "nuclei profile not found" });
      return;
    }

    logger.info({ event: "nuclei_profile.updated", nuclei_profile_id: profile.id, updated_by: req.session.username });
    recordAudit("nuclei_profile.updated", req.session.username, req.ip, { nuclei_profile_id: profile.id });

    res.json(profile);
  })
);

nucleiProfilesRouter.delete(
  "/:id",
  asyncHandler(async (req, res) => {
    if (!uuidSchema.safeParse(req.params.id).success) {
      res.status(400).json({ error: "invalid nuclei profile id" });
      return;
    }

    // Safe to hard-delete for the same reason as scan_profiles - see
    // resolve.ts.
    const result = await db.deleteFrom("nuclei_profiles").where("id", "=", req.params.id).executeTakeFirst();
    if (result.numDeletedRows === 0n) {
      res.status(404).json({ error: "nuclei profile not found" });
      return;
    }

    logger.info({ event: "nuclei_profile.deleted", nuclei_profile_id: req.params.id, deleted_by: req.session.username });
    recordAudit("nuclei_profile.deleted", req.session.username, req.ip, { nuclei_profile_id: req.params.id });

    res.status(204).end();
  })
);
