import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";

// Operator+admin, like tags/rescan - this is day-to-day monitoring, not
// infrastructure config (that's what the Webhooks page's admin-only
// targets are for; a saved search only ever fires webhooks that are
// already configured there).
export const savedSearchesRouter = Router();
savedSearchesRouter.use(requireAuth, requireOperator);

const uuidSchema = z.string().uuid();

savedSearchesRouter.get("/", asyncHandler(async (req, res) => {
  const searches = await db
    .selectFrom("saved_searches")
    .select(["id", "name", "filters", "created_by", "created_at"])
    .orderBy("created_at", "desc")
    .execute();
  res.json(searches);
}));

// What each saved search currently matches, for the page that lists them.
// Deliberately not folded into GET / above: that response feeds the
// dashboard's own sidebar on every page load, where the only thing needed
// is the name to click, and counting matches means running every saved
// search's full host query.
//
// The counts come from saved_search_matches - the checker's own record of
// what matched at its last pass - rather than by re-running each search
// here. That is the honest number: it is exactly the set the next
// saved_search.match alert will be diffed against, so a host listed here
// will not alert again, and one that is not will. Re-running the queries
// would produce a fresher number that answers a different question.
savedSearchesRouter.get("/matches", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);

  let query = db
    .selectFrom("saved_search_matches")
    .innerJoin("hosts", "hosts.id", "saved_search_matches.host_id")
    .select([
      "saved_search_matches.saved_search_id as saved_search_id",
      "hosts.id as host_id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "hosts.last_seen_at as last_seen_at",
    ])
    .orderBy("hosts.last_seen_at", "desc");
  if (allowed) {
    query = query.where("hosts.scanner_agent_id", "in", allowed);
  }
  const rows = await query.execute();

  const bySearch = new Map<string, Array<{ id: string; ip: string; hostname: string | null; lastSeenAt: Date }>>();
  for (const row of rows) {
    const list = bySearch.get(row.saved_search_id) ?? [];
    list.push({ id: row.host_id, ip: String(row.ip), hostname: row.hostname, lastSeenAt: row.last_seen_at });
    bySearch.set(row.saved_search_id, list);
  }

  res.json(
    [...bySearch.entries()].map(([savedSearchId, hosts]) => ({
      savedSearchId,
      matchCount: hosts.length,
      // A short preview rather than every match: this page is a list of
      // searches, and one search matching four hundred hosts should not
      // push the next one off the screen. The search itself is one click
      // away for the full list.
      hosts: hosts.slice(0, 5),
    }))
  );
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
