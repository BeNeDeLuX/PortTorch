import { db } from "../db";
import { logger } from "../logger";
import { dispatchWebhook } from "../webhooks/dispatch";
import { applyHostFilters, parseHostFilterParams } from "../search/routes";

// More time-sensitive than the hourly cert-expiry check (a security team
// generally wants prompt notice that a new host now matches, e.g., "port
// 3389 open AND tag=prod"), but not so frequent it risks overlapping runs
// or hammering the DB with every saved search's query back to back.
const CHECK_INTERVAL_MS = 5 * 60_000;

export function startSavedSearchAlerts(): void {
  setInterval(() => {
    tick().catch((err) => logger.error({ event: "saved_search.tick_failed", err: err instanceof Error ? err.message : String(err) }));
  }, CHECK_INTERVAL_MS);
}

async function tick(): Promise<void> {
  const searches = await db.selectFrom("saved_searches").select(["id", "name", "filters"]).execute();
  for (const search of searches) {
    await checkOne(search);
  }
}

async function checkOne(search: { id: string; name: string; filters: Record<string, unknown> }): Promise<void> {
  const filterParams = parseHostFilterParams(search.filters);

  let query = db.selectFrom("hosts").select(["hosts.id as id", "hosts.ip as ip", "hosts.hostname as hostname"]) as any;
  query = applyHostFilters(query, filterParams);
  const currentMatches: Array<{ id: string; ip: string; hostname: string | null }> = await query.execute();

  const previousRows = await db
    .selectFrom("saved_search_matches")
    .select(["host_id"])
    .where("saved_search_id", "=", search.id)
    .execute();
  const previousIds = new Set(previousRows.map((r) => r.host_id));
  const currentIds = new Set(currentMatches.map((m) => m.id));

  const newMatches = currentMatches.filter((m) => !previousIds.has(m.id));
  const removedIds = [...previousIds].filter((id) => !currentIds.has(id));

  for (const host of newMatches) {
    const target = host.hostname || host.ip;
    await dispatchWebhook("saved_search.match", `Saved search "${search.name}" matched a new host: ${target}`, {
      savedSearchId: search.id,
      savedSearchName: search.name,
      hostId: host.id,
      hostIp: host.ip,
      hostHostname: host.hostname,
    });
    logger.info({
      event: "saved_search.new_match",
      saved_search_id: search.id,
      saved_search_name: search.name,
      host_id: host.id,
      host_ip: host.ip,
    });
  }

  if (removedIds.length === 0 && newMatches.length === 0) {
    return;
  }

  await db.transaction().execute(async (trx) => {
    if (removedIds.length > 0) {
      await trx
        .deleteFrom("saved_search_matches")
        .where("saved_search_id", "=", search.id)
        .where("host_id", "in", removedIds)
        .execute();
    }
    if (newMatches.length > 0) {
      await trx
        .insertInto("saved_search_matches")
        .values(newMatches.map((m) => ({ saved_search_id: search.id, host_id: m.id })))
        .execute();
    }
  });
}
