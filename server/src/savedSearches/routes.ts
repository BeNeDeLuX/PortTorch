import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";

// Operator+admin, like tags/rescan - this is day-to-day monitoring, not
// infrastructure config (that's what the Webhooks page's admin-only
// targets are for; a saved search only ever fires webhooks that are
// already configured there).
export const savedSearchesRouter = Router();
savedSearchesRouter.use(requireAuth, requireOperator);

const uuidSchema = z.string().uuid();

savedSearchesRouter.get("/", asyncHandler(async (_req, res) => {
  const searches = await db
    .selectFrom("saved_searches")
    .select(["id", "name", "filters", "created_by", "created_at"])
    .orderBy("created_at", "desc")
    .execute();
  res.json(searches);
}));

// filters is stored exactly as the frontend's URLSearchParams for the
// current view (minus "page") - the same flat, comma-joined-string shape
// parseHostFilterParams already knows how to read from req.query, so the
// periodic checker (savedSearches/checker.ts) can reuse it with zero
// translation and zero risk of drifting from what the dashboard itself
// would show for the same filters.
const createSavedSearchSchema = z.object({
  name: z.string().trim().min(1).max(100),
  filters: z.record(z.string(), z.string()),
});

savedSearchesRouter.post("/", asyncHandler(async (req, res) => {
  const parsed = createSavedSearchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const search = await db
    .insertInto("saved_searches")
    .values({
      name: parsed.data.name,
      filters: JSON.stringify(parsed.data.filters),
      created_by: req.session.username!,
    })
    .returning(["id", "name", "filters", "created_by", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({ event: "saved_search.created", saved_search_id: search.id, name: search.name, created_by: req.session.username });
  recordAudit("saved_search.created", req.session.username, req.ip, { saved_search_id: search.id, name: search.name });

  res.status(201).json(search);
}));

savedSearchesRouter.delete("/:id", asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid saved search id" });
    return;
  }

  const result = await db.deleteFrom("saved_searches").where("id", "=", req.params.id).executeTakeFirst();
  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "saved search not found" });
    return;
  }

  logger.info({ event: "saved_search.deleted", saved_search_id: req.params.id, deleted_by: req.session.username });
  recordAudit("saved_search.deleted", req.session.username, req.ip, { saved_search_id: req.params.id });

  res.status(204).end();
}));
