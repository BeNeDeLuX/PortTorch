import { db } from "../db";

// Every audit_log.details field shaped like an entity id, mapped to how
// to resolve it to a human-readable name for display - kept as one small
// table here rather than touching every recordAudit call site to also
// inline a name (a handful already redundantly do, e.g. schedule.created
// already carries scanner_agent_name). A purely batched, read-time
// lookup handles two things inlining at write time never could: it works
// retroactively on audit rows written before this existed, and it still
// resolves correctly for an entity that's since been hard-deleted
// (scanner agents/users/webhooks/scan profiles/api tokens/saved searches
// can all be deleted - see CLAUDE.md's various "preserves history" notes)
// by falling back to DELETED instead of silently showing nothing.

type NameTable = "scanner_agents" | "webhooks" | "scan_profiles" | "api_tokens" | "saved_searches";

const STRING_ID_KEYS: { key: string; table: NameTable }[] = [
  { key: "scanner_agent_id", table: "scanner_agents" },
  { key: "webhook_id", table: "webhooks" },
  { key: "scan_profile_id", table: "scan_profiles" },
  { key: "api_token_id", table: "api_tokens" },
  { key: "saved_search_id", table: "saved_searches" },
];

// The one array-valued id field in use today (user.created/
// user.scanner_access_updated's scanner_agent_ids) - resolved to a
// comma-joined list of names rather than one entry per id, since the
// details column itself already only has room for a single string value
// per key.
const STRING_ID_ARRAY_KEYS: { key: string; table: NameTable }[] = [{ key: "scanner_agent_ids", table: "scanner_agents" }];

// Bare, not "(deleted)" - the frontend already wraps every resolved
// name in its own parentheses (AuditDetails in pages/Audit.tsx), so a
// pre-parenthesized label here would render as a confusing double
// "((deleted))".
const DELETED = "deleted";

// schedule_id/scan_job_id/scan_request_id/comment_id/exclude_id are
// deliberately not resolved here - none of those tables have a "name"
// column of their own (a schedule/job/request/comment/exclude IS its
// id, not a named thing with a separate identity), so there's nothing a
// lookup could add beyond what recordAudit already logs inline (e.g.
// exclude.created already logs kind+value directly).

async function fetchNameMap(table: NameTable, ids: string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const rows = await db.selectFrom(table).select(["id", "name"]).where("id", "in", ids).execute();
  return new Map(rows.map((r) => [r.id, r.name]));
}

async function fetchUserNameMap(ids: number[]): Promise<Map<number, string>> {
  if (ids.length === 0) return new Map();
  const rows = await db.selectFrom("users").select(["id", "username"]).where("id", "in", ids).execute();
  return new Map(rows.map((r) => [r.id, r.username]));
}

async function fetchHostNameMap(ids: string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const rows = await db.selectFrom("hosts").select(["id", "ip", "hostname"]).where("id", "in", ids).execute();
  return new Map(rows.map((r) => [r.id, r.hostname ?? r.ip]));
}

// Resolves every recognized id field across a whole page of audit
// entries in one batch of queries (a handful of `WHERE id = ANY(...)`
// lookups total, not one query per row per id) and returns a parallel
// array of {key -> resolved name} maps, one per input entry, in the
// same order. An entry with nothing resolvable gets an empty object,
// never null/undefined, so the frontend never needs a null-check.
export async function resolveAuditNames(entries: { details: Record<string, unknown> | null }[]): Promise<Record<string, string>[]> {
  const idsByTable: Record<NameTable, Set<string>> = {
    scanner_agents: new Set(),
    webhooks: new Set(),
    scan_profiles: new Set(),
    api_tokens: new Set(),
    saved_searches: new Set(),
  };
  const userIds = new Set<number>();
  const hostIds = new Set<string>();

  for (const { details } of entries) {
    if (!details) continue;
    for (const { key, table } of STRING_ID_KEYS) {
      const id = details[key];
      if (typeof id === "string" && id) idsByTable[table].add(id);
    }
    for (const { key, table } of STRING_ID_ARRAY_KEYS) {
      const ids = details[key];
      if (Array.isArray(ids)) {
        for (const id of ids) {
          if (typeof id === "string" && id) idsByTable[table].add(id);
        }
      }
    }
    if (typeof details.host_id === "string" && details.host_id) hostIds.add(details.host_id);
    if (typeof details.user_id === "number") userIds.add(details.user_id);
  }

  const [scannerAgentNames, webhookNames, scanProfileNames, apiTokenNames, savedSearchNames, hostNames, userNames] = await Promise.all([
    fetchNameMap("scanner_agents", [...idsByTable.scanner_agents]),
    fetchNameMap("webhooks", [...idsByTable.webhooks]),
    fetchNameMap("scan_profiles", [...idsByTable.scan_profiles]),
    fetchNameMap("api_tokens", [...idsByTable.api_tokens]),
    fetchNameMap("saved_searches", [...idsByTable.saved_searches]),
    fetchHostNameMap([...hostIds]),
    fetchUserNameMap([...userIds]),
  ]);

  const nameMapsByTable: Record<NameTable, Map<string, string>> = {
    scanner_agents: scannerAgentNames,
    webhooks: webhookNames,
    scan_profiles: scanProfileNames,
    api_tokens: apiTokenNames,
    saved_searches: savedSearchNames,
  };

  return entries.map(({ details }) => {
    const resolved: Record<string, string> = {};
    if (!details) return resolved;

    for (const { key, table } of STRING_ID_KEYS) {
      const id = details[key];
      if (typeof id === "string" && id) {
        resolved[key] = nameMapsByTable[table].get(id) ?? DELETED;
      }
    }
    for (const { key, table } of STRING_ID_ARRAY_KEYS) {
      const ids = details[key];
      if (Array.isArray(ids) && ids.length > 0) {
        resolved[key] = ids
          .map((id) => (typeof id === "string" ? nameMapsByTable[table].get(id) ?? DELETED : String(id)))
          .join(", ");
      }
    }
    if (typeof details.host_id === "string" && details.host_id) {
      resolved.host_id = hostNames.get(details.host_id) ?? DELETED;
    }
    if (typeof details.user_id === "number") {
      resolved.user_id = userNames.get(details.user_id) ?? DELETED;
    }
    return resolved;
  });
}
