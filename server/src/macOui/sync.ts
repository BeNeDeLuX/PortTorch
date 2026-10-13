import { sql } from "kysely";
import { db } from "../db";
import { logger } from "../logger";
import { outboundGet } from "../lib/outbound";
import { caBundle } from "../settings/caCertificates";
import { parseNmapMacPrefixes, parseOuiCsv } from "./parse";

// Two sources, merged. nmap's nmap-mac-prefixes (about 52,000 prefixes
// including the finer MA-M/MA-S blocks, 1.4 MB) comes first, because its
// names are the ones nmap writes into hosts.mac_vendor - the IEEE's own
// full names ("Cisco Systems, Inc" for nmap's "Cisco Systems") would list
// one manufacturer twice. The IEEE MA-L registry (4 MB) then fills only the
// prefixes nmap's copy does not have yet: it lags new assignments - on
// the first real sync, 1,390 of 53,475 prefixes came only from the IEEE.
// A prefix in neither list gets no vendor rather than a guess; a real
// Cisco engine-ID MAC (00:D4:78) is registered in no IEEE registry at all
// (MA-L, MA-M, MA-S and CID all checked).
//
// Both change by a few dozen entries a week, so they are fetched weekly;
// the daily tick only checks whether a week has passed.
export const NMAP_PREFIXES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes";
export const IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv";
const CHECK_INTERVAL_MS = 24 * 60 * 60_000;
const REFRESH_AFTER_MS = 7 * 24 * 60 * 60_000;

// A response this small is a truncated download or an error page, not the
// registry - replacing a good table with it would erase every vendor name.
const MIN_ENTRIES = 1000;

export async function syncMacOui(
  urls: { nmap: string; ieee: string } = { nmap: NMAP_PREFIXES_URL, ieee: IEEE_OUI_URL },
  minEntries = MIN_ENTRIES
): Promise<{ entries: number; fromIeee: number }> {
  await db.updateTable("mac_oui_state").set({ last_attempt_at: new Date() }).where("id", "=", 1).execute();
  try {
    const ca = await caBundle();
    const fetchText = async (url: string) => {
      const res = await outboundGet(url, { ca, headers: { Accept: "text/plain, text/csv, */*" }, timeoutMs: 120_000 });
      if (!res.ok) throw new Error(`${url}: ${res.error ?? `status ${res.status}`}`);
      return res.body ?? "";
    };
    const map = parseNmapMacPrefixes(await fetchText(urls.nmap));
    if (map.size < minEntries) throw new Error(`only ${map.size} entries from nmap-mac-prefixes - not replacing the table`);
    // The IEEE half only adds what nmap lacks, so a failure there costs
    // the newest prefixes, not the table: logged, not fatal.
    let fromIeee = 0;
    try {
      for (const [prefix, vendor] of parseOuiCsv(await fetchText(urls.ieee))) {
        if (!map.has(prefix)) {
          map.set(prefix, vendor);
          fromIeee++;
        }
      }
    } catch (err) {
      logger.warn({ event: "mac_oui.ieee_failed", err: err instanceof Error ? err.message : String(err) });
    }

    const rows = [...map].map(([prefix, vendor]) => ({ prefix, vendor }));
    await db.transaction().execute(async (trx) => {
      await trx.deleteFrom("mac_oui").execute();
      for (let i = 0; i < rows.length; i += 2000) {
        await trx.insertInto("mac_oui").values(rows.slice(i, i + 2000)).execute();
      }
    });
    await db
      .updateTable("mac_oui_state")
      .set({ synced_at: new Date(), entries: rows.length, last_error: null })
      .where("id", "=", 1)
      .execute();
    logger.info({ event: "mac_oui.synced", entries: rows.length, from_ieee: fromIeee });
    return { entries: rows.length, fromIeee };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db.updateTable("mac_oui_state").set({ last_error: message }).where("id", "=", 1).execute();
    throw err;
  }
}

// The vendor for a MAC, as SQL: the longest registered prefix of it (9,
// 7, then 6 hex digits - a 36-bit MA-S block belongs to a different
// company than the 24-bit block it was carved from), unless the address is
// locally administered (the 0x02 bit of the first byte - randomised phone
// and VM addresses), whose prefix belongs to nobody and would name a
// stranger.
function vendorFor(column: "mac_address" | "derived_mac_address") {
  const hex = sql.raw(`replace(upper(hosts.${column}), ':', '')`);
  return sql<string | null>`(
    SELECT o.vendor FROM mac_oui o
    WHERE o.prefix IN (substring(${hex} from 1 for 9), substring(${hex} from 1 for 7), substring(${hex} from 1 for 6))
      AND (get_byte(decode(substring(${hex} from 1 for 2), 'hex'), 0) & 2) = 0
    ORDER BY length(o.prefix) DESC
    LIMIT 1
  )`;
}

// Fills in the manufacturer wherever a host has a MAC but no vendor for
// it: nmap names the vendor of an ARP-resolved MAC itself, so this mostly
// covers the derived ones. Never overwrites a vendor that is already set.
// Scoped to one scanner's hosts when called after an ingest, fleet-wide
// after a sync.
export async function fillMacVendors(scannerAgentId?: string): Promise<number> {
  let filled = 0;
  for (const [mac, vendor] of [
    ["mac_address", "mac_vendor"],
    ["derived_mac_address", "derived_mac_vendor"],
  ] as const) {
    let query = db
      .updateTable("hosts")
      .set({ [vendor]: vendorFor(mac) })
      .where(mac, "is not", null)
      .where((eb) => eb.or([eb(vendor, "is", null), eb(vendor, "=", "")]))
      .where(sql<boolean>`${vendorFor(mac)} IS NOT NULL`);
    if (scannerAgentId) query = query.where("scanner_agent_id", "=", scannerAgentId);
    const result = await query.executeTakeFirst();
    filled += Number(result.numUpdatedRows ?? 0);
  }
  return filled;
}

async function tick(): Promise<void> {
  const state = await db.selectFrom("mac_oui_state").selectAll().where("id", "=", 1).executeTakeFirst();
  const due = !state?.synced_at || Date.now() - state.synced_at.getTime() > REFRESH_AFTER_MS;
  if (due) await syncMacOui();
  const filled = await fillMacVendors();
  if (filled > 0) logger.info({ event: "mac_oui.vendors_filled", hosts: filled });
}

export function startMacOuiSync(): void {
  const run = () =>
    tick().catch((err) => logger.error({ event: "mac_oui.sync_failed", err: err instanceof Error ? err.message : String(err) }));
  run();
  setInterval(run, CHECK_INTERVAL_MS);
}
