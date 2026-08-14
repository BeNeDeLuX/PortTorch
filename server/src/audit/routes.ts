import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { parseDateOnly } from "../lib/dateOnly";
import { resolveAuditNames } from "./resolveNames";

export const auditRouter = Router();
auditRouter.use(requireAdmin);

auditRouter.get("/", asyncHandler(async (req, res) => {
  const limit = Math.min(500, Math.max(1, parseInt(String(req.query.limit ?? "200"), 10) || 200));
  const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
  const from = typeof req.query.from === "string" ? req.query.from.trim() : "";
  const until = typeof req.query.until === "string" ? req.query.until.trim() : "";

  let query = db.selectFrom("audit_log").selectAll();

  if (q) {
    // Free text across event/actor/source_ip and the details blob (e.g. a
    // host id or IP mentioned inside details) - casts to text so this
    // works the same way regardless of column type (source_ip is inet,
    // details is jsonb).
    query = query.where((eb) =>
      eb.or([
        eb("event", "ilike", `%${q}%`),
        eb("actor", "ilike", `%${q}%`),
        sql<boolean>`source_ip::text ilike ${`%${q}%`}`,
        sql<boolean>`details::text ilike ${`%${q}%`}`,
      ])
    );
  }

  // Same "YYYY-MM-DD" date-only convention as the dashboard's "Last seen
  // from/until" filter (search/routes.ts) - from/until here filter on
  // created_at instead of last_seen_at, but share the same parsing so a
  // date picked here means the same thing it would there.
  if (from) {
    const after = parseDateOnly(from);
    if (after) {
      query = query.where("created_at", ">=", after);
    }
  }
  if (until) {
    const before = parseDateOnly(until);
    if (before) {
      const endOfDay = new Date(before.getTime() + 24 * 60 * 60_000);
      query = query.where("created_at", "<", endOfDay);
    }
  }

  const entries = await query.orderBy("created_at", "desc").limit(limit).execute();

  // Resolves every id-shaped field in each entry's details (scanner
  // agent, host, user, webhook, ...) to a human name in one batch of
  // lookups - see resolveNames.ts for why this happens here, at read
  // time, rather than baking a name into details at write time.
  const resolvedNames = await resolveAuditNames(entries);
  res.json(entries.map((entry, i) => ({ ...entry, resolvedNames: resolvedNames[i] })));
}));
