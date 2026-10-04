import { sql } from "kysely";
import { db } from "../db";
import { policyViolations } from "./evaluate";

// Shared by the dashboard routes and the External API - see
// baselines/service.ts for why. `allowed` is a scanner restriction in the
// shape both auth chains produce (null = unrestricted).
//
// A restricted caller sees policies over every scanner (violations
// narrowed to its own scanners) and those scoped to a scanner it may see.
export function policyQuery(allowed: string[] | null) {
  let query = db
    .selectFrom("port_policies as p")
    .leftJoin("scanner_agents as sa", "sa.id", "p.scanner_agent_id")
    .select([
      "p.id",
      "p.name",
      sql<string>`p.network::text`.as("network"),
      "p.scanner_agent_id",
      "sa.name as scanner_agent_name",
      "p.mode",
      "p.ports",
      "p.note",
      "p.enabled",
      "p.created_by",
      "p.created_at",
      "p.updated_at",
    ]);
  if (allowed) {
    query = query.where((eb) => eb.or([eb("p.scanner_agent_id", "is", null), eb("p.scanner_agent_id", "in", allowed)]));
  }
  return query;
}

export async function listPolicySummaries(allowed: string[] | null) {
  const rows = await policyQuery(allowed).orderBy("p.network").orderBy("p.name").execute();
  const out = [];
  for (const p of rows) {
    const { items, truncated } = await policyViolations(p, allowed);
    out.push({ ...p, violations: items.length, violatingHosts: new Set(items.map((v) => v.hostId)).size, truncated });
  }
  return out;
}

export async function policyWithViolations(id: string, allowed: string[] | null) {
  const policy = await policyQuery(allowed).where("p.id", "=", id).executeTakeFirst();
  if (!policy) return null;
  return { policy, violations: await policyViolations(policy, allowed) };
}
