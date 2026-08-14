import { Router } from "express";
import { sql, type Selectable } from "kysely";
import { db } from "../db";
import type { AuditLogTable } from "../db/types";
import { requireAdmin } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { parseDateOnly } from "../lib/dateOnly";
import { resolveAuditNames } from "./resolveNames";

type AuditLogRow = Selectable<AuditLogTable>;

export const auditRouter = Router();
auditRouter.use(requireAdmin);

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

interface AuditFilterParams {
  q: string;
  from: string;
  until: string;
  events: string[];
  actors: string[];
}

function parseAuditFilterParams(req: { query: Record<string, unknown> }): AuditFilterParams {
  return {
    q: typeof req.query.q === "string" ? req.query.q.trim() : "",
    from: typeof req.query.from === "string" ? req.query.from.trim() : "",
    until: typeof req.query.until === "string" ? req.query.until.trim() : "",
    // Comma-joined, same convention as every other multi-value filter in
    // this app (port/service/tag on the dashboard, scannerAgentIds, ...).
    events: typeof req.query.events === "string" ? req.query.events.split(",").filter(Boolean) : [],
    actors: typeof req.query.actors === "string" ? req.query.actors.split(",").filter(Boolean) : [],
  };
}

// Shared between the paginated list below and export.csv, so an export
// always matches exactly what the current search/date-range view shows -
// same "one filter function, every reader of it stays in sync" pattern
// as search/routes.ts's applyHostFilters (query typed any there too, for
// the same reason: a Kysely query builder's own type changes shape with
// every .where() call, which a reusable filter function can't express
// without fighting the type system for no real safety benefit here).
function applyAuditFilters(query: any, { q, from, until, events, actors }: AuditFilterParams): any {
  let result = query;

  if (events.length > 0) {
    result = result.where("event", "in", events);
  }
  if (actors.length > 0) {
    result = result.where("actor", "in", actors);
  }

  if (q) {
    // Free text across event/actor/source_ip and the details blob (e.g. a
    // host id or IP mentioned inside details) - casts to text so this
    // works the same way regardless of column type (source_ip is inet,
    // details is jsonb).
    const like = `%${q}%`;
    result = result.where((eb: any) =>
      eb.or([
        eb("event", "ilike", like),
        eb("actor", "ilike", like),
        sql<boolean>`source_ip::text ilike ${like}`,
        sql<boolean>`details::text ilike ${like}`,
      ])
    );
  }

  // Same "YYYY-MM-DD" date-only convention as the dashboard's "Last seen
  // from/until" filter (search/routes.ts) - from/until here filter on
  // created_at instead of last_seen_at, but share the same parsing so a
  // date picked here means the same thing it would there.
  if (from) {
    const after = parseDateOnly(from);
    if (after) result = result.where("created_at", ">=", after);
  }
  if (until) {
    const before = parseDateOnly(until);
    if (before) {
      const endOfDay = new Date(before.getTime() + 24 * 60 * 60_000);
      result = result.where("created_at", "<", endOfDay);
    }
  }

  return result;
}

// Distinct event strings actually present in the table, for the
// frontend's event-type filter dropdown - not a hardcoded enum, since
// audit events are free-form strings written from ~20 different call
// sites across the codebase (see audit/log.ts's recordAudit), unlike
// webhook events (a genuinely closed, deliberately curated set). A
// hardcoded list here would drift the moment a new recordAudit call
// site was added elsewhere and forgot to also update this one.
auditRouter.get("/events", asyncHandler(async (req, res) => {
  const rows = await db.selectFrom("audit_log").select("event").distinct().orderBy("event", "asc").execute();
  res.json(rows.map((r) => r.event));
}));

// Same idea for the actor filter - distinct non-null actors actually
// present (a system-initiated entry, e.g. retention.host_purged, has
// actor = null and is deliberately excluded here, since "null" isn't a
// selectable filter option).
auditRouter.get("/actors", asyncHandler(async (req, res) => {
  const rows = await db
    .selectFrom("audit_log")
    .select("actor")
    .distinct()
    .where("actor", "is not", null)
    .orderBy("actor", "asc")
    .execute();
  res.json(rows.map((r) => r.actor));
}));

auditRouter.get("/", asyncHandler(async (req, res) => {
  const page = Math.max(1, parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(
    MAX_PAGE_SIZE,
    Math.max(1, parseInt(String(req.query.pageSize ?? DEFAULT_PAGE_SIZE), 10) || DEFAULT_PAGE_SIZE)
  );
  const filters = parseAuditFilterParams(req);

  const countQuery = applyAuditFilters(db.selectFrom("audit_log"), filters);
  const { count } = await countQuery.select(sql<number>`count(*)`.as("count")).executeTakeFirstOrThrow();

  const listQuery = applyAuditFilters(db.selectFrom("audit_log").selectAll(), filters);
  const entries = await listQuery
    .orderBy("created_at", "desc")
    .limit(pageSize)
    .offset((page - 1) * pageSize)
    .execute();

  // Resolves every id-shaped field in each entry's details (scanner
  // agent, host, user, webhook, ...) to a human name in one batch of
  // lookups - see resolveNames.ts for why this happens here, at read
  // time, rather than baking a name into details at write time.
  const resolvedNames = await resolveAuditNames(entries);
  res.json({
    items: entries.map((entry: AuditLogRow, i: number) => ({ ...entry, resolvedNames: resolvedNames[i] })),
    total: Number(count),
    page,
    pageSize,
  });
}));

function csvEscape(value: string | number): string {
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// Exports every entry matching the current q/from/until filters (no
// pagination applied) - same "the export always matches exactly what the
// current view is scoped to" contract as the Dashboard's hosts export.
auditRouter.get("/export.csv", asyncHandler(async (req, res) => {
  const filters = parseAuditFilterParams(req);
  const query = applyAuditFilters(db.selectFrom("audit_log").selectAll(), filters);
  const entries = await query.orderBy("created_at", "desc").execute();

  const header = ["time", "event", "actor", "source_ip", "details"];
  const rows = entries.map((e: AuditLogRow) =>
    [
      e.created_at.toISOString(),
      e.event,
      e.actor ?? "",
      e.source_ip ?? "",
      e.details ? JSON.stringify(e.details) : "",
    ]
      .map(csvEscape)
      .join(",")
  );

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="audit-log.csv"');
  res.status(200).send([header.join(","), ...rows].join("\r\n"));
}));
