import { sql } from "kysely";
import { db } from "../db";
import { baselineDeviations, deviationKeys } from "./deviations";

// Shared by the dashboard routes and the External API, so a baseline means
// the same thing - and is scoped the same way - whichever way it is read.
// `allowed` is a scanner restriction in the shape both auth chains produce
// (null = unrestricted).

// A baseline belongs to a caller's view when it covers every scanner (the
// deviations shown are then narrowed to what the caller may see) or names
// a scanner the caller may see.
export function baselineQuery(allowed: string[] | null) {
  let query = db
    .selectFrom("network_baselines as b")
    .leftJoin("scanner_agents as sa", "sa.id", "b.scanner_agent_id")
    .select([
      "b.id",
      sql<string>`b.network::text`.as("network"),
      "b.scanner_agent_id",
      "sa.name as scanner_agent_name",
      "b.note",
      "b.approved_at",
      "b.approved_by",
      "b.created_at",
    ]);
  if (allowed) {
    query = query.where((eb) => eb.or([eb("b.scanner_agent_id", "is", null), eb("b.scanner_agent_id", "in", allowed)]));
  }
  return query;
}

// Every baseline with how far it has drifted. Counts only - the lists are
// one call away, and a list of baselines should not ship every host of
// every network.
export async function listBaselineSummaries(allowed: string[] | null) {
  const rows = await baselineQuery(allowed).orderBy("b.network").execute();
  const out = [];
  for (const b of rows) {
    const changes = await baselineDeviations(b, allowed);
    out.push({
      ...b,
      deviations: {
        newHosts: changes.newHosts.items.length,
        openedPorts: changes.openedPorts.items.length,
        closedPorts: changes.closedPorts.items.length,
        unseenHosts: changes.unseenHosts.items.length,
        truncated:
          changes.newHosts.truncated ||
          changes.openedPorts.truncated ||
          changes.closedPorts.truncated ||
          changes.unseenHosts.truncated,
        alerting: deviationKeys(changes).length,
      },
      scansSinceApproval: changes.scansInPeriod,
    });
  }
  return out;
}

export async function baselineWithChanges(id: string, allowed: string[] | null) {
  const baseline = await baselineQuery(allowed).where("b.id", "=", id).executeTakeFirst();
  if (!baseline) return null;
  return { baseline, changes: await baselineDeviations(baseline, allowed) };
}

// Accepts every current deviation by moving the approval moment to now.
// alerted_keys is cleared with it: nothing deviates from the new moment,
// so there is nothing left that was already reported. Returns the
// baseline, or null when it is not visible to the caller.
export async function approveBaseline(id: string, allowed: string[] | null, actor: string | null, note?: string | null) {
  const visible = await baselineQuery(allowed).where("b.id", "=", id).executeTakeFirst();
  if (!visible) return null;
  await db
    .updateTable("network_baselines")
    .set({
      approved_at: new Date(),
      approved_by: actor,
      alerted_keys: [],
      ...(note !== undefined ? { note } : {}),
    })
    .where("id", "=", visible.id)
    .execute();
  return visible;
}
