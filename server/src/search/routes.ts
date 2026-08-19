import net from "net";
import { Router } from "express";
import { sql } from "kysely";
import { z } from "zod";
import { db } from "../db";
import { requireAdmin, requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { isIPv4Cidr, isIPv6Cidr } from "../lib/net";
import { isStale } from "../lib/staleness";
import { getAppSettings } from "../settings/appSettings";
import { parseDateOnly, toDateOnlyString } from "../lib/dateOnly";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { requestRescan } from "../rescan";
import { NOT_A_LIVE_RISK_STATES, cveNotTriaged } from "../findingTriage/sqlFilters";
import { NSEProfileSelection } from "../scanProfiles/resolve";
import { NucleiProfileSelection } from "../nucleiProfiles/resolve";
import { singleParam } from "../lib/reqParams";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      // Set by hostsRouter.param("id", ...) below - a host already
      // resolved to exist and, if the session is scanner-restricted,
      // confirmed to belong to an allowed scanner agent. Every route below
      // that takes a host :id can trust this instead of re-fetching/re-
      // checking it.
      hostRecord?: { id: string; scanner_agent_id: string | null };
    }
  }
}

export const hostsRouter = Router();
hostsRouter.use(requireAuth);

const uuidSchema = z.string().uuid();

// Runs once per request for every route on this router with a `:id`
// param (i.e. every host-by-id route below) - centralizes the uuid
// validation, existence check, and scanner-restriction check that each of
// those routes previously had to repeat (and could forget to). 404, not
// 403, when a restricted session's host exists but belongs to a scanner
// outside its allowed set - this must not confirm to the caller that an
// out-of-scope host exists at all.
hostsRouter.param("id", (req, res, next, id) => {
  (async () => {
    if (!uuidSchema.safeParse(id).success) {
      res.status(400).json({ error: "invalid host id" });
      return;
    }
    const host = await db.selectFrom("hosts").select(["id", "scanner_agent_id"]).where("id", "=", id).executeTakeFirst();
    if (!host) {
      res.status(404).json({ error: "host not found" });
      return;
    }
    const allowed = getAllowedScannerAgentIds(req);
    if (allowed && (!host.scanner_agent_id || !allowed.includes(host.scanner_agent_id))) {
      res.status(404).json({ error: "host not found" });
      return;
    }
    req.hostRecord = host;
    next();
  })().catch(next);
});

// Exported so saved-search alerting (server/src/savedSearches/checker.ts)
// can reuse the exact same filter parsing/query logic - otherwise a saved
// search's "matches" could silently drift from what the dashboard itself
// would show for the same filters.
export interface HostFilterParams {
  q: string;
  ports: number[];
  services: string[];
  tags: string[];
  osFamily: string;
  deviceType: string;
  hideEmpty: boolean;
  hasScreenshot: boolean;
  lastSeenAfter: string;
  lastSeenBefore: string;
  scannerAgentIds: string[];
  // Scopes to specific host ids, AND'd in alongside every other filter
  // here rather than replacing them - used by the export routes'
  // "export only the selected hosts" option (Dashboard's bulk-select
  // checkboxes). In practice the selected ids are already a subset of
  // whatever the current filters match (selection happens from the
  // already-filtered list), so this is a no-op narrowing in the common
  // case, but composing it as one more AND'd condition (rather than a
  // separate ids-only code path per export route) means it can never
  // accidentally bypass the allowedScannerAgentIds restriction below.
  ids: string[];
}

// Comma-separated (?port=21,3389) rather than repeated query keys - simpler
// to build from the frontend's URLSearchParams and to reason about here.
function parseCommaList(value: unknown): string[] {
  if (typeof value !== "string" || !value.trim()) return [];
  return value.split(",").map((v) => v.trim()).filter(Boolean);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseHostFilterParams(query: Record<string, unknown>): HostFilterParams {
  return {
    q: typeof query.q === "string" ? query.q.trim() : "",
    ports: parseCommaList(query.port)
      .map((p) => parseInt(p, 10))
      .filter((p) => !Number.isNaN(p)),
    services: parseCommaList(query.service),
    tags: parseCommaList(query.tag),
    osFamily: typeof query.osFamily === "string" ? query.osFamily.trim() : "",
    deviceType: typeof query.deviceType === "string" ? query.deviceType.trim() : "",
    hideEmpty: query.hideEmpty === "true" || query.hideEmpty === "1",
    hasScreenshot: query.hasScreenshot === "true" || query.hasScreenshot === "1",
    lastSeenAfter: typeof query.lastSeenAfter === "string" ? query.lastSeenAfter.trim() : "",
    lastSeenBefore: typeof query.lastSeenBefore === "string" ? query.lastSeenBefore.trim() : "",
    scannerAgentIds: parseCommaList(query.scannerAgentId),
    // Invalid entries are silently dropped rather than causing a 400 -
    // a malformed id in the list just means that one host is excluded,
    // not that the whole export request fails.
    ids: parseCommaList(query.ids).filter((id) => UUID_RE.test(id)),
  };
}

// Shared between the JSON host list and the CSV export - both need the
// exact same filters, otherwise the two views would silently disagree on
// what "matches" (this bit us once already with the open-port-state
// filtering, see CLAUDE.md). Kysely's builder type gets unwieldy to spell
// out generically here since the two callers select different columns, so
// this is intentionally loosely typed.
export function applyHostFilters(
  query: any,
  {
    q,
    ports,
    services,
    tags,
    osFamily,
    deviceType,
    hideEmpty,
    hasScreenshot,
    lastSeenAfter,
    lastSeenBefore,
    scannerAgentIds,
    ids,
  }: HostFilterParams,
  // Session-based scanner restriction (server/src/auth/scannerScope.ts),
  // separate from the user-chosen scannerAgentIds filter above - this is
  // AND'd in unconditionally regardless of what the user picks, so an
  // out-of-scope scannerAgentIds selection combines with it to correctly
  // return zero rows rather than leaking another scanner's hosts. null =
  // unrestricted (the default: an admin, or any caller - like the saved-
  // search checker - with no user session to restrict by).
  allowedScannerAgentIds: string[] | null = null
): any {
  if (q) {
    const isIp = net.isIP(q) !== 0;
    // hosts.ip <<= ::cidr is already dual-stack-correct Postgres syntax -
    // the only reason an IPv6 CIDR search didn't work before was this JS
    // gate being IPv4-only.
    const isCidr = isIPv4Cidr(q) || isIPv6Cidr(q);
    query = query.where((eb: any) =>
      eb.or([
        ...(isIp ? [eb("hosts.ip", "=", q)] : []),
        ...(isCidr ? [sql<boolean>`hosts.ip <<= ${q}::cidr`] : []),
        eb("hosts.hostname", "ilike", `%${q}%`),
        eb.exists(
          eb
            .selectFrom("current_host_ports as chp")
            .select("chp.id")
            .whereRef("chp.host_id", "=", "hosts.id")
            .where("chp.state", "=", "open")
            .where((eb2: any) =>
              eb2.or([
                eb2("chp.service_name", "ilike", `%${q}%`),
                eb2("chp.service_product", "ilike", `%${q}%`),
                eb2("chp.banner", "ilike", `%${q}%`),
                // Catches a filename in an anonymous FTP listing or an SMB
                // share name (see scanner's "ftp-anon"/"smb-enum-shares"
                // NSE scripts) - same reasoning as banner above: this is
                // free text a scanner captured, not a structured field, so
                // it belongs in the free-text match, not its own filter.
                eb2("chp.ftp_anon_listing", "ilike", `%${q}%`),
                eb2("chp.smb_shares", "ilike", `%${q}%`),
                // Same idea for the long tail of other enumeration
                // scripts (NFS/rsync/LDAP listings, open-database checks -
                // see chp.nse_extra) - a jsonb array of {id, output}
                // objects rather than a plain column, so this unnests it
                // rather than a plain ilike (same jsonb-unnest pattern as
                // the CVE id match further down in this function).
                sql<boolean>`chp.nse_extra is not null and exists (
                  select 1 from jsonb_array_elements(chp.nse_extra) as nse_elem
                  where nse_elem->>'output' ilike ${`%${q}%`}
                )`,
              ])
            )
        ),
        // Text OCR'd from HTTP(S)/RDP screenshots by the scanner
        // (pipeline/ocr.go, Tesseract) - catches page/login content that
        // never appears in a banner or HTTP header, e.g. text baked into
        // a background image or an RDP login screen.
        eb.exists(
          eb.selectFrom("screenshots as s").select("s.id").whereRef("s.host_id", "=", "hosts.id").where("s.ocr_text", "ilike", `%${q}%`)
        ),
        eb.exists(
          eb
            .selectFrom("rdp_screenshots as rs")
            .select("rs.id")
            .whereRef("rs.host_id", "=", "hosts.id")
            .where("rs.ocr_text", "ilike", `%${q}%`)
        ),
        // Matches a CVE id (e.g. "CVE-2008-3844", or just a substring of
        // one) against whatever's cached in cve_cache for this host's open
        // ports' CPEs - see server/src/cve/sync.ts for how that cache is
        // populated. Kysely has no first-class jsonb helpers, so this is
        // raw SQL rather than the query builder, same as the CIDR match
        // above.
        sql<boolean>`
          exists (
            select 1 from current_host_ports chp2
            join cve_cache cc on cc.cpe = any(chp2.cpes)
            where chp2.host_id = hosts.id
              and chp2.state = 'open'
              and exists (
                select 1 from jsonb_array_elements(cc.cves) as cve_elem
                where cve_elem->>'id' ilike ${`%${q}%`}
              )
          )
        `,
      ])
    );
  }

  // Each selected port/service/tag adds its own EXISTS check, and chained
  // .where() calls AND together - so selecting port 21 and port 3389 means
  // "has 21 open AND has 3389 open", not "has either". That's the point of
  // multi-select here: narrowing to hosts matching everything picked, not
  // widening to hosts matching anything picked.
  for (const port of ports) {
    query = query.where((eb: any) =>
      eb.exists(
        eb
          .selectFrom("current_host_ports as chp")
          .select("chp.id")
          .whereRef("chp.host_id", "=", "hosts.id")
          .where("chp.port", "=", port)
          .where("chp.state", "=", "open")
      )
    );
  }

  for (const service of services) {
    query = query.where((eb: any) =>
      eb.exists(
        eb
          .selectFrom("current_host_ports as chp")
          .select("chp.id")
          .whereRef("chp.host_id", "=", "hosts.id")
          .where("chp.service_name", "=", service)
          .where("chp.state", "=", "open")
      )
    );
  }

  for (const tag of tags) {
    query = query.where((eb: any) =>
      eb.exists(
        eb.selectFrom("host_tags as ht").select("ht.id").whereRef("ht.host_id", "=", "hosts.id").where("ht.tag", "=", tag)
      )
    );
  }

  if (osFamily) {
    query = query.where("hosts.os_family", "=", osFamily);
  }

  if (deviceType) {
    query = query.where("hosts.device_type", "=", deviceType);
  }

  // A host's identity is (ip, scanner_agent_id), not ip alone (see
  // CLAUDE.md's "Database shape") - this lets the dashboard narrow down
  // to one or more scanners' hosts, e.g. to look at a few network segments
  // in isolation without every other scanner's same-ip hosts mixed in.
  if (scannerAgentIds.length > 0) {
    query = query.where("hosts.scanner_agent_id", "in", scannerAgentIds);
  }

  if (allowedScannerAgentIds) {
    query = query.where("hosts.scanner_agent_id", "in", allowedScannerAgentIds);
  }

  if (ids.length > 0) {
    query = query.where("hosts.id", "in", ids);
  }

  if (hideEmpty) {
    query = query.where((eb: any) =>
      eb.exists(
        eb
          .selectFrom("current_host_ports as chp")
          .select("chp.id")
          .whereRef("chp.host_id", "=", "hosts.id")
          .where("chp.state", "=", "open")
      )
    );
  }

  if (hasScreenshot) {
    query = query.where((eb: any) =>
      eb.or([
        eb.exists(
          eb.selectFrom("screenshots as s").select("s.id").whereRef("s.host_id", "=", "hosts.id")
        ),
        eb.exists(
          eb.selectFrom("rdp_screenshots as rs").select("rs.id").whereRef("rs.host_id", "=", "hosts.id")
        ),
      ])
    );
  }

  if (lastSeenAfter) {
    const after = parseDateOnly(lastSeenAfter);
    if (after) {
      query = query.where("hosts.last_seen_at", ">=", after);
    }
  }

  if (lastSeenBefore) {
    const before = parseDateOnly(lastSeenBefore);
    if (before) {
      // Inclusive of the whole selected day, not just midnight.
      const endOfDay = new Date(before.getTime() + 24 * 60 * 60_000);
      query = query.where("hosts.last_seen_at", "<", endOfDay);
    }
  }

  return query;
}

function csvEscape(value: string | number): string {
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

hostsRouter.get("/", asyncHandler(async (req, res) => {
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);
  const page = Math.max(1, parseInt(String(req.query.page ?? "1"), 10) || 1);
  const pageSize = Math.min(
    MAX_PAGE_SIZE,
    Math.max(1, parseInt(String(req.query.pageSize ?? DEFAULT_PAGE_SIZE), 10) || DEFAULT_PAGE_SIZE)
  );

  const allowed = getAllowedScannerAgentIds(req);

  let countQuery = db.selectFrom("hosts").select(sql<number>`count(distinct hosts.id)`.as("count"));
  countQuery = applyHostFilters(countQuery, filters, allowed);
  const { count } = await countQuery.executeTakeFirstOrThrow();

  let query = db
    .selectFrom("hosts")
    .leftJoin("current_host_ports", "current_host_ports.host_id", "hosts.id")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select([
      "hosts.id as id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "hosts.last_seen_at as last_seen_at",
      "hosts.os_family as os_family",
      "hosts.device_type as device_type",
      "hosts.mac_address as mac_address",
      "hosts.mac_vendor as mac_vendor",
      // A host's identity is (ip, scanner_agent_id), not ip alone - two
      // different scanners (different networks) can each have a real
      // device at the same ip, so this is surfaced here to tell those
      // apart in the dashboard rather than showing two indistinguishable
      // rows with the same ip. scanner_agent_id itself is included too,
      // not just the name, so the dashboard can filter by clicking a
      // host's own "via <scanner>" text without a name-to-id lookup.
      "scanner_agents.name as scanner_agent_name",
      "hosts.scanner_agent_id as scanner_agent_id",
      sql<number>`count(distinct current_host_ports.port) filter (where current_host_ports.state = 'open')`.as(
        "open_port_count"
      ),
      sql<string | null>`(
        select shot.id from (
          select id, captured_at from screenshots where host_id = hosts.id
          union all
          select id, captured_at from rdp_screenshots where host_id = hosts.id
        ) shot
        order by shot.captured_at desc
        limit 1
      )`.as("thumbnail_id"),
      sql<"http" | "rdp" | null>`(
        select shot.kind from (
          select id, 'http' as kind, captured_at from screenshots where host_id = hosts.id
          union all
          select id, 'rdp' as kind, captured_at from rdp_screenshots where host_id = hosts.id
        ) shot
        order by shot.captured_at desc
        limit 1
      )`.as("thumbnail_kind"),
      // Same correlated-subquery approach as thumbnail_id/thumbnail_kind
      // above (scoped per host, not part of the GROUP BY) - the same
      // cve_cache/current_host_ports join vulnerabilities/routes.ts and
      // search/routes.ts's own GET /:id already use, just aggregated to
      // a count/max/exists instead of returned as individual rows, so the
      // host list can show a risk indicator without a second round trip.
      sql<number>`(
        select count(distinct cve_elem->>'id')
        from current_host_ports chp2
        join cve_cache cc2 on cc2.cpe = ANY(chp2.cpes)
        cross join lateral jsonb_array_elements(cc2.cves) as cve_elem
        where chp2.host_id = hosts.id and chp2.state = 'open'
          and ${cveNotTriaged("hosts.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
      )`.as("cve_count"),
      sql<number | null>`(
        select max((cve_elem->>'cvssScore')::float)
        from current_host_ports chp2
        join cve_cache cc2 on cc2.cpe = ANY(chp2.cpes)
        cross join lateral jsonb_array_elements(cc2.cves) as cve_elem
        where chp2.host_id = hosts.id and chp2.state = 'open'
          and ${cveNotTriaged("hosts.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
      )`.as("max_cvss_score"),
      sql<boolean>`exists (
        select 1
        from current_host_ports chp2
        join cve_cache cc2 on cc2.cpe = ANY(chp2.cpes)
        cross join lateral jsonb_array_elements(cc2.cves) as cve_elem
        join kev_cache kc2 on kc2.cve_id = cve_elem->>'id'
        where chp2.host_id = hosts.id and chp2.state = 'open'
          and ${cveNotTriaged("hosts.id", "cve_elem->>'id'", NOT_A_LIVE_RISK_STATES)}
      )`.as("has_kev"),
    ])
    .groupBy([
      "hosts.id",
      "hosts.ip",
      "hosts.hostname",
      "hosts.last_seen_at",
      "hosts.os_family",
      "hosts.device_type",
      "hosts.mac_address",
      "hosts.mac_vendor",
      "hosts.scanner_agent_id",
      "scanner_agents.name",
    ])
    .orderBy("hosts.last_seen_at", "desc");

  query = applyHostFilters(query, filters, allowed);

  const items = await query
    .limit(pageSize)
    .offset((page - 1) * pageSize)
    .execute();

  // cve_count is a Postgres bigint (count(distinct ...)), which
  // node-postgres returns as a string, not a number - same "count columns
  // need an explicit Number() wrap before res.json()" reasoning as
  // ScanHistory's own screenshot/rdp_screenshot counts (see CLAUDE.md).
  // Confirmed as a real bug here too, not just reasoned about: the
  // frontend's `cve_count === 0` check silently never matched a string
  // "0", so a host with zero CVEs rendered a stray "0 CVEs" badge instead
  // of no badge at all.
  const itemsWithNumericCveCount = items.map((h) => ({ ...h, cve_count: Number(h.cve_count) }));

  res.json({ items: itemsWithNumericCveCount, total: Number(count), page, pageSize });
}));

// "host": one row per host, open_port_count only - a quick fleet summary.
// "port": one row per host+open-port (host columns repeated per row) - a
// flat asset inventory suitable for pivoting/filtering by port/service in
// a spreadsheet. Both share the same filters, so an export always matches
// exactly what the dashboard's current view is scoped to.
hostsRouter.get("/export.csv", asyncHandler(async (req, res) => {
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);
  const allowed = getAllowedScannerAgentIds(req);
  const detail = req.query.detail === "port" ? "port" : "host";

  if (detail === "port") {
    let query = db
      .selectFrom("hosts")
      .innerJoin("current_host_ports", "current_host_ports.host_id", "hosts.id")
      .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
      .select([
        "hosts.ip as ip",
        "hosts.hostname as hostname",
        "scanner_agents.name as scanner_agent_name",
        "hosts.os_family as os_family",
        "hosts.device_type as device_type",
        "current_host_ports.port as port",
        "current_host_ports.protocol as protocol",
        "current_host_ports.service_name as service_name",
        "current_host_ports.service_product as service_product",
        "current_host_ports.service_version as service_version",
        "hosts.last_seen_at as last_seen_at",
      ])
      .where("current_host_ports.state", "=", "open")
      .orderBy("hosts.last_seen_at", "desc")
      .orderBy("current_host_ports.port");

    query = applyHostFilters(query, filters, allowed);

    // Higher than the host-summary cap below since this is one row per
    // open port, not per host - a host with 10 open ports is 10 rows here.
    const rows = await query.limit(20_000).execute();

    const lines = [
      "ip,hostname,scanner_agent,os_family,device_type,port,protocol,service_name,service_product,service_version,last_seen_at",
      ...rows.map((r) =>
        [
          r.ip,
          r.hostname ?? "",
          r.scanner_agent_name ?? "",
          r.os_family ?? "",
          r.device_type ?? "",
          r.port,
          r.protocol,
          r.service_name ?? "",
          r.service_product ?? "",
          r.service_version ?? "",
          new Date(r.last_seen_at).toISOString(),
        ]
          .map(csvEscape)
          .join(",")
      ),
    ];

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="hosts-ports.csv"');
    res.status(200).send(lines.join("\r\n"));
    return;
  }

  let query = db
    .selectFrom("hosts")
    .leftJoin("current_host_ports", "current_host_ports.host_id", "hosts.id")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select([
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "hosts.last_seen_at as last_seen_at",
      "hosts.os_family as os_family",
      "hosts.device_type as device_type",
      // Same reasoning as the host list above - two different scanners can
      // each have a real device at the same ip, so this needs to be in the
      // export to tell those rows apart.
      "scanner_agents.name as scanner_agent_name",
      sql<number>`count(distinct current_host_ports.port) filter (where current_host_ports.state = 'open')`.as(
        "open_port_count"
      ),
    ])
    .groupBy([
      "hosts.id",
      "hosts.ip",
      "hosts.hostname",
      "hosts.last_seen_at",
      "hosts.os_family",
      "hosts.device_type",
      "scanner_agents.name",
    ])
    .orderBy("hosts.last_seen_at", "desc");

  query = applyHostFilters(query, filters, allowed);

  // Higher than the on-screen list's 200-row preview cap, since an export
  // is expected to actually contain everything matching the filter.
  const hosts = await query.limit(2000).execute();

  const lines = [
    "ip,hostname,scanner_agent,os_family,device_type,open_port_count,last_seen_at",
    ...hosts.map((h) =>
      [
        h.ip,
        h.hostname ?? "",
        h.scanner_agent_name ?? "",
        h.os_family ?? "",
        h.device_type ?? "",
        h.open_port_count,
        new Date(h.last_seen_at).toISOString(),
      ]
        .map(csvEscape)
        .join(",")
    ),
  ];

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="hosts.csv"');
  res.status(200).send(lines.join("\r\n"));
}));

// JSON's third shape alongside the two CSV ones above: one object per host
// (same filters, same host set as the "host" CSV detail level) with a
// nested `openPorts` array - CSV can't express that nesting without either
// flattening to one row per port (the "port" detail level) or losing the
// port data entirely (the "host" summary level), so JSON exists
// specifically for a caller that wants both the host-level fields and the
// full port list in one file, structured rather than flattened.
hostsRouter.get("/export.json", asyncHandler(async (req, res) => {
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);
  const allowed = getAllowedScannerAgentIds(req);

  let hostsQuery = db
    .selectFrom("hosts")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .select([
      "hosts.id as id",
      "hosts.ip as ip",
      "hosts.hostname as hostname",
      "hosts.last_seen_at as last_seen_at",
      "hosts.os_family as os_family",
      "hosts.os_name as os_name",
      "hosts.device_type as device_type",
      "scanner_agents.name as scanner_agent_name",
    ])
    .orderBy("hosts.last_seen_at", "desc");

  hostsQuery = applyHostFilters(hostsQuery, filters, allowed);

  // Same cap as the "host" CSV detail level above - one row per host here too.
  const hosts = await hostsQuery.limit(2000).execute();

  const hostIds = hosts.map((h) => h.id);
  const ports =
    hostIds.length > 0
      ? await db
          .selectFrom("current_host_ports")
          .select(["host_id", "port", "protocol", "service_name", "service_product", "service_version"])
          .where("host_id", "in", hostIds)
          .where("state", "=", "open")
          .execute()
      : [];
  const portsByHostId = new Map<string, typeof ports>();
  for (const p of ports) {
    const list = portsByHostId.get(p.host_id) ?? [];
    list.push(p);
    portsByHostId.set(p.host_id, list);
  }

  const result = hosts.map((h) => ({
    ip: h.ip,
    hostname: h.hostname,
    scannerAgent: h.scanner_agent_name,
    osFamily: h.os_family,
    osName: h.os_name,
    deviceType: h.device_type,
    lastSeenAt: h.last_seen_at,
    openPorts: (portsByHostId.get(h.id) ?? []).map((p) => ({
      port: p.port,
      protocol: p.protocol,
      serviceName: p.service_name,
      serviceProduct: p.service_product,
      serviceVersion: p.service_version,
    })),
  }));

  res.setHeader("Content-Disposition", 'attachment; filename="hosts.json"');
  res.status(200).json(result);
}));

// Whether any dashboard filter is actually active - used by the facets
// endpoints below to skip the extra filtering work entirely on a plain,
// unfiltered page load (the overwhelmingly common case), rather than
// paying for a join + applyHostFilters on every request regardless.
function hasActiveHostFilters(f: HostFilterParams): boolean {
  return Boolean(
    f.q ||
      f.ports.length ||
      f.services.length ||
      f.tags.length ||
      f.osFamily ||
      f.deviceType ||
      f.hideEmpty ||
      f.hasScreenshot ||
      f.lastSeenAfter ||
      f.lastSeenBefore ||
      f.scannerAgentIds.length
  );
}

// Each facet's own counts are computed against whatever the *other* active
// filters currently narrow the host list down to (e.g. a keyword search or
// a selected tag), excluding that facet's own dimension - standard faceted
// search semantics: a keyword search should live-update the Ports sidebar,
// but a facet doesn't hide its own alternatives just because one of its
// own values is already selected. `current_host_ports`/`host_tags` aren't
// scoped by `ip`/`hostname`/etc. on their own, so applyHostFilters (written
// against the `hosts` table) is applied through a join to `hosts` rather
// than needing a separate host-id lookup.
async function computePortFacet(filters: HostFilterParams, allowed: string[] | null, limit?: number) {
  let query = db
    .selectFrom("current_host_ports")
    .select(["current_host_ports.port as port", sql<number>`count(distinct current_host_ports.host_id)`.as("count")])
    .where("current_host_ports.state", "=", "open");
  const scoped = { ...filters, ports: [] };
  // A restriction must apply even when nothing else does - otherwise a
  // restricted user with no other filter selected would skip the join
  // entirely and see fleet-wide counts, leaking other scanners' data.
  if (hasActiveHostFilters(scoped) || allowed) {
    query = applyHostFilters(query.innerJoin("hosts", "hosts.id", "current_host_ports.host_id"), scoped, allowed);
  }
  query = query.groupBy("current_host_ports.port").orderBy("count", "desc").orderBy("current_host_ports.port");
  if (limit) query = query.limit(limit);
  const rows = await query.execute();
  return rows.map((p) => ({ port: p.port, count: Number(p.count) }));
}

hostsRouter.get("/facets", asyncHandler(async (req, res) => {
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);
  const allowed = getAllowedScannerAgentIds(req);

  const ports = await computePortFacet(filters, allowed, 10);

  let servicesQuery = db
    .selectFrom("current_host_ports")
    .select(["current_host_ports.service_name as service_name", sql<number>`count(distinct current_host_ports.host_id)`.as("count")])
    .where("current_host_ports.state", "=", "open")
    .where("current_host_ports.service_name", "is not", null)
    .where("current_host_ports.service_name", "!=", "");
  const servicesFilters = { ...filters, services: [] };
  if (hasActiveHostFilters(servicesFilters) || allowed) {
    servicesQuery = applyHostFilters(servicesQuery.innerJoin("hosts", "hosts.id", "current_host_ports.host_id"), servicesFilters, allowed);
  }
  const services = await servicesQuery
    .groupBy("current_host_ports.service_name")
    .orderBy("count", "desc")
    .orderBy("current_host_ports.service_name")
    .limit(10)
    .execute();

  let tagsQuery = db
    .selectFrom("host_tags")
    .select(["host_tags.tag as tag", sql<number>`count(distinct host_tags.host_id)`.as("count")]);
  const tagsFilters = { ...filters, tags: [] };
  if (hasActiveHostFilters(tagsFilters) || allowed) {
    tagsQuery = applyHostFilters(tagsQuery.innerJoin("hosts", "hosts.id", "host_tags.host_id"), tagsFilters, allowed);
  }
  const tags = await tagsQuery.groupBy("host_tags.tag").orderBy("count", "desc").orderBy("host_tags.tag").limit(20).execute();

  let osQuery = db
    .selectFrom("hosts")
    .select(["os_family", sql<number>`count(*)`.as("count")])
    .where("os_family", "is not", null);
  const osFilters = { ...filters, osFamily: "" };
  if (hasActiveHostFilters(osFilters) || allowed) {
    osQuery = applyHostFilters(osQuery, osFilters, allowed);
  }
  const osFamilies = await osQuery.groupBy("os_family").orderBy("count", "desc").orderBy("os_family").limit(20).execute();

  let deviceQuery = db
    .selectFrom("hosts")
    .select(["device_type", sql<number>`count(*)`.as("count")])
    .where("device_type", "is not", null);
  const deviceFilters = { ...filters, deviceType: "" };
  if (hasActiveHostFilters(deviceFilters) || allowed) {
    deviceQuery = applyHostFilters(deviceQuery, deviceFilters, allowed);
  }
  const deviceTypes = await deviceQuery.groupBy("device_type").orderBy("count", "desc").orderBy("device_type").limit(20).execute();

  res.json({
    ports,
    services: services.map((s) => ({ service: s.service_name as string, count: Number(s.count) })),
    tags: tags.map((t) => ({ tag: t.tag, count: Number(t.count) })),
    osFamilies: osFamilies.map((o) => ({ osFamily: o.os_family as string, count: Number(o.count) })),
    deviceTypes: deviceTypes.map((d) => ({ deviceType: d.device_type as string, count: Number(d.count) })),
  });
}));

// The main /facets response caps the Ports list at the top 10 (by how
// many hosts have each open) to keep the sidebar a manageable size - a
// port that's only open on one or two hosts (e.g. a single misc service)
// falls off that list entirely even though it's real, correctly-recorded
// data. This is the "show more" escape hatch: same query, same shape,
// just without the limit - fetched on demand rather than folded into the
// main facets call, since it's a strictly bigger, rarely-needed payload.
// Shares computePortFacet with the main /facets route above so both stay
// scoped to the current filters identically - only the limit differs.
hostsRouter.get("/facets/ports", asyncHandler(async (req, res) => {
  const filters = parseHostFilterParams(req.query as Record<string, unknown>);
  res.json(await computePortFacet(filters, getAllowedScannerAgentIds(req)));
}));

hostsRouter.get("/:id", asyncHandler(async (req, res) => {
  // hostsRouter.param("id", ...) above already guarantees this host exists
  // and, if restricted, is in scope - this re-fetch is just for the richer
  // column set (scanner_agent_name) the detail page needs.
  const host = await db
    .selectFrom("hosts")
    .leftJoin("scanner_agents", "scanner_agents.id", "hosts.scanner_agent_id")
    .selectAll("hosts")
    // A host's identity is (ip, scanner_agent_id), not ip alone - surfaced
    // here so the detail page can show which scanner/network this
    // particular row belongs to, same reasoning as the host list above.
    .select(["scanner_agents.name as scanner_agent_name"])
    .where("hosts.id", "=", req.params.id)
    .executeTakeFirstOrThrow();

  const rawPorts = await db
    .selectFrom("current_host_ports")
    .selectAll()
    .where("host_id", "=", req.params.id)
    .where("state", "=", "open")
    .orderBy("port")
    .execute();

  // CVE data is synced separately (server/src/cve/sync.ts, daily against
  // the NVD API) and cached by CPE string - this just looks up whatever's
  // already cached for the CPEs this host's ports were fingerprinted with,
  // no live NVD call on the request path.
  const allCpes = [...new Set(rawPorts.flatMap((p) => p.cpes ?? []))];
  const cveRows = allCpes.length > 0 ? await db.selectFrom("cve_cache").select(["cpe", "cves"]).where("cpe", "in", allCpes).execute() : [];
  const cvesByCpe = new Map(cveRows.map((r) => [r.cpe, r.cves]));

  // EPSS is synced/cached separately, keyed by CVE id rather than CPE (see
  // cve/epssSync.ts) - looked up for every distinct CVE id these ports'
  // cached CVE entries reference, same "read from cache, no live call on
  // the request path" pattern as the NVD data above.
  const allCveIds = [...new Set([...cvesByCpe.values()].flatMap((cves) => cves.map((c) => c.id)))];
  const epssRows = allCveIds.length > 0 ? await db.selectFrom("epss_cache").select(["cve_id", "epss", "percentile"]).where("cve_id", "in", allCveIds).execute() : [];
  const epssByCveId = new Map(epssRows.map((r) => [r.cve_id, r]));

  // KEV is synced/cached separately too, also keyed by CVE id (see
  // cve/kevSync.ts) - same "read from cache, no live call on the request
  // path" pattern as CVE/EPSS above.
  const kevRows = allCveIds.length > 0 ? await db.selectFrom("kev_cache").select(["cve_id", "date_added", "known_ransomware_campaign_use"]).where("cve_id", "in", allCveIds).execute() : [];
  const kevByCveId = new Map(kevRows.map((r) => [r.cve_id, r]));

  // Triage state is attached here but never used to *hide* anything -
  // unlike the fleet-wide Vulnerabilities page (which filters triaged
  // findings out by default), a host's own detail page is the complete
  // record of what was found on it, so a dismissed CVE stays listed and
  // is simply marked as decided.
  const triageRows = await db
    .selectFrom("finding_triage")
    .select(["cve_id", "state", "note"])
    .where("host_id", "=", req.params.id)
    .where("kind", "=", "cve")
    .execute();
  const triageByCveId = new Map(triageRows.map((r) => [r.cve_id!, r]));

  const ports = rawPorts.map((p) => {
    const vulnerabilities = new Map<
      string,
      (typeof cveRows)[number]["cves"][number] & { epssScore: number | null; epssPercentile: number | null; kevDateAdded: string | null; kevKnownRansomwareCampaignUse: string | null; triageState: string | null; triageNote: string | null }
    >();
    for (const cpe of p.cpes ?? []) {
      for (const cve of cvesByCpe.get(cpe) ?? []) {
        const epss = epssByCveId.get(cve.id);
        const kev = kevByCveId.get(cve.id);
        const triage = triageByCveId.get(cve.id);
        vulnerabilities.set(cve.id, {
          ...cve,
          epssScore: epss?.epss ?? null,
          epssPercentile: epss?.percentile ?? null,
          kevDateAdded: toDateOnlyString(kev?.date_added ?? null),
          kevKnownRansomwareCampaignUse: kev?.known_ransomware_campaign_use ?? null,
          triageState: triage?.state ?? null,
          triageNote: triage?.note ?? null,
        });
      }
    }
    return { ...p, vulnerabilities: [...vulnerabilities.values()] };
  });

  // Joined to scan_jobs/scanner_agents so each history entry (and the
  // timeline grouped from it) can show which scanner produced it - "which
  // scanner found this asset" is otherwise not answerable from the
  // observation row alone.
  const history = await db
    .selectFrom("host_port_observations")
    .innerJoin("scan_jobs", "scan_jobs.id", "host_port_observations.scan_job_id")
    .leftJoin("scanner_agents", "scanner_agents.id", "scan_jobs.scanner_agent_id")
    .select([
      "host_port_observations.id as id",
      "host_port_observations.host_id as host_id",
      "host_port_observations.scan_job_id as scan_job_id",
      "host_port_observations.port as port",
      "host_port_observations.protocol as protocol",
      "host_port_observations.state as state",
      "host_port_observations.service_name as service_name",
      "host_port_observations.service_product as service_product",
      "host_port_observations.service_version as service_version",
      "host_port_observations.extra_info as extra_info",
      "host_port_observations.os_type as os_type",
      "host_port_observations.cpes as cpes",
      "host_port_observations.banner as banner",
      "host_port_observations.observed_at as observed_at",
      "scanner_agents.name as scanner_agent_name",
    ])
    .where("host_port_observations.host_id", "=", req.params.id)
    .orderBy("host_port_observations.observed_at", "desc")
    .limit(500)
    .execute();

  const screenshots = await db
    .selectFrom("screenshots")
    .selectAll()
    .where("host_id", "=", req.params.id)
    .orderBy("captured_at", "desc")
    .execute();

  const rdpScreenshots = await db
    .selectFrom("rdp_screenshots")
    .selectAll()
    .where("host_id", "=", req.params.id)
    .orderBy("captured_at", "desc")
    .execute();

  const lastScanRequestRow = await db
    .selectFrom("scan_requests")
    .selectAll()
    .where("host_id", "=", req.params.id)
    .orderBy("created_at", "desc")
    .executeTakeFirst();

  // Only "pending" (never claimed - the target scanner hasn't polled in a
  // while) and "claimed" (claimed but never completed - the scanner died
  // mid-scan) can go stale; "completed"/"failed" are terminal states and
  // are never flagged regardless of age. Measured from claimed_at once
  // claimed, since a request can legitimately sit "pending" for a while
  // on a scanner with a long pollIntervalSeconds before that.
  const lastScanRequest = lastScanRequestRow
    ? {
        ...lastScanRequestRow,
        is_stale:
          (lastScanRequestRow.status === "pending" || lastScanRequestRow.status === "claimed") &&
          isStale(
            lastScanRequestRow.claimed_at ?? lastScanRequestRow.created_at,
            (await getAppSettings()).staleScanThresholdMinutes
          ),
      }
    : null;

  // Only the most recent capture per port (TLS) or per port+key type
  // (SSH, since a port can have multiple host key types at once) - the
  // full history stays in the DB but isn't shown here.
  const tlsCertificates = await db
    .selectFrom("tls_certificates")
    .selectAll()
    .distinctOn("port")
    .where("host_id", "=", req.params.id)
    .orderBy("port")
    .orderBy("captured_at", "desc")
    .execute();

  const sshHostKeys = await db
    .selectFrom("ssh_host_keys")
    .selectAll()
    .distinctOn(["port", "key_type"])
    .where("host_id", "=", req.params.id)
    .orderBy("port")
    .orderBy("key_type")
    .orderBy("captured_at", "desc")
    .execute();

  // Same "most recent per identity" convention as tlsCertificates/
  // sshHostKeys above - a finding stays a distinct row per scan (see the
  // nuclei_profiles migration's own comment), identity here is
  // (template_id, matched_at) since the same template can match multiple
  // URLs/paths on the same host.
  const nucleiFindings = await db
    .selectFrom("nuclei_findings")
    .selectAll()
    .distinctOn(["template_id", "matched_at"])
    .where("host_id", "=", req.params.id)
    .orderBy("template_id")
    .orderBy("matched_at")
    .orderBy("observed_at", "desc")
    .execute();

  const tags = await db
    .selectFrom("host_tags")
    .select(["tag"])
    .where("host_id", "=", req.params.id)
    .orderBy("tag")
    .execute();

  // Append-only log, not a single overwritable field - every comment is
  // kept with its author and timestamp rather than replacing the last one.
  const comments = await db
    .selectFrom("host_comments")
    .select(["id", "author", "body", "created_at"])
    .where("host_id", "=", req.params.id)
    .orderBy("created_at", "desc")
    .execute();

  res.json({
    host,
    ports,
    history,
    screenshots,
    rdpScreenshots,
    tlsCertificates,
    sshHostKeys,
    nucleiFindings,
    tags: tags.map((t) => t.tag),
    comments,
    lastScanRequest: lastScanRequest ?? null,
  });
}));

const tagSchema = z.object({ tag: z.string().trim().min(1).max(64) });

hostsRouter.post("/:id/tags", requireOperator, asyncHandler(async (req, res) => {
  const parsed = tagSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  await db
    .insertInto("host_tags")
    .values({ host_id: singleParam(req.params.id), tag: parsed.data.tag })
    .onConflict((oc) => oc.columns(["host_id", "tag"]).doNothing())
    .execute();

  logger.info({
    event: "host.tag_added",
    host_id: req.params.id,
    tag: parsed.data.tag,
    added_by: req.session.username,
  });
  recordAudit("host.tag_added", req.session.username, req.ip, { host_id: req.params.id, tag: parsed.data.tag });

  res.status(201).json({ tag: parsed.data.tag });
}));

hostsRouter.delete("/:id/tags/:tag", requireOperator, asyncHandler(async (req, res) => {
  const result = await db
    .deleteFrom("host_tags")
    .where("host_id", "=", req.params.id)
    .where("tag", "=", req.params.tag)
    .executeTakeFirst();

  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "tag not found" });
    return;
  }

  logger.info({
    event: "host.tag_removed",
    host_id: req.params.id,
    tag: req.params.tag,
    removed_by: req.session.username,
  });
  recordAudit("host.tag_removed", req.session.username, req.ip, { host_id: req.params.id, tag: req.params.tag });

  res.status(204).end();
}));

const probeHostnameSchema = z.object({ hostname: z.string().trim().min(1).max(253).nullable() });

// A manual override the scanner uses instead of the bare IP for TLS SNI
// and the gowitness screenshot URL - see CLAUDE.md's "Manual probe
// hostname override" section for why the discovered IP alone isn't always
// enough (SNI-based vhost routing rejecting an unmatched hostname).
// Day-to-day host annotation like tags/comments, not a fleet-wide policy
// change, so requireOperator rather than requireAdmin.
hostsRouter.patch("/:id/probe-hostname", requireOperator, asyncHandler(async (req, res) => {
  const parsed = probeHostnameSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  await db
    .updateTable("hosts")
    .set({ probe_hostname: parsed.data.hostname })
    .where("id", "=", req.params.id)
    .execute();

  logger.info({
    event: "host.probe_hostname_set",
    host_id: req.params.id,
    probe_hostname: parsed.data.hostname,
    set_by: req.session.username,
  });
  recordAudit("host.probe_hostname_set", req.session.username, req.ip, {
    host_id: req.params.id,
    probe_hostname: parsed.data.hostname,
  });

  res.status(200).json({ probe_hostname: parsed.data.hostname });
}));

const nseProfileSelectionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("default") }),
  z.object({ kind: z.literal("all_safe") }),
  z.object({ kind: z.literal("custom"), profileId: z.string().uuid() }),
]);

const nucleiProfileSelectionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("off") }),
  z.object({ kind: z.literal("safe") }),
  z.object({ kind: z.literal("custom"), profileId: z.string().uuid() }),
]);

const rescanBodySchema = z.object({
  profile: nseProfileSelectionSchema.optional(),
  nucleiProfile: nucleiProfileSelectionSchema.optional(),
});

hostsRouter.post("/:id/rescan", requireOperator, asyncHandler(async (req, res) => {
  const parsedBody = rescanBodySchema.safeParse(req.body ?? {});
  if (!parsedBody.success) {
    res.status(400).json({ error: parsedBody.error.flatten() });
    return;
  }
  const profile: NSEProfileSelection = parsedBody.data.profile ?? { kind: "default" };
  const nucleiProfile: NucleiProfileSelection = parsedBody.data.nucleiProfile ?? { kind: "off" };
  const outcome = await requestRescan(singleParam(req.params.id), req.session.username ?? null, profile, nucleiProfile);
  if (!outcome.ok) {
    res.status(outcome.status).json({ error: outcome.error });
    return;
  }

  logger.info({
    event: "rescan.requested",
    scan_request_id: outcome.request.id,
    host_id: req.params.id,
    requested_by: req.session.username,
    source_ip: req.ip,
  });
  recordAudit("rescan.requested", req.session.username, req.ip, { host_id: req.params.id });

  res.status(201).json(outcome.request);
}));

// Marks a stuck scan_request "failed" so the host detail page stops
// showing it as pending/claimed and the "Rescan" button unlocks again -
// same rationale as scanJobs/routes.ts's "/dismiss": the scanner isn't
// told, and if it's actually still alive, its own PATCH
// /api/ingest/scan-requests/:id has no status precondition (matches on
// id + scanner_agent_id only) and will happily overwrite this "failed"
// guess with its real outcome - which is what we want, since the
// scanner's own report should always win over an admin's guess. Re-checks
// is_stale server-side rather than trusting the client's last poll.
hostsRouter.post("/:id/rescan/dismiss", requireOperator, asyncHandler(async (req, res) => {
  const request = await db
    .selectFrom("scan_requests")
    .select(["id", "status", "created_at", "claimed_at"])
    .where("host_id", "=", req.params.id)
    .orderBy("created_at", "desc")
    .executeTakeFirst();
  if (!request) {
    res.status(404).json({ error: "no scan request found for this host" });
    return;
  }
  const stale =
    (request.status === "pending" || request.status === "claimed") &&
    isStale(request.claimed_at ?? request.created_at, (await getAppSettings()).staleScanThresholdMinutes);
  if (!stale) {
    res.status(409).json({ error: "scan request is not stale" });
    return;
  }

  await db
    .updateTable("scan_requests")
    .set({ status: "failed", completed_at: new Date().toISOString() })
    .where("id", "=", request.id)
    .execute();

  logger.info({ event: "scan_request.dismissed", scan_request_id: request.id, host_id: req.params.id, dismissed_by: req.session.username });
  recordAudit("scan_request.dismissed", req.session.username, req.ip, { scan_request_id: request.id, host_id: req.params.id });

  res.status(204).end();
}));

const commentSchema = z.object({ body: z.string().trim().min(1).max(10_000) });

hostsRouter.post("/:id/comments", requireOperator, asyncHandler(async (req, res) => {
  const parsed = commentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const comment = await db
    .insertInto("host_comments")
    .values({ host_id: singleParam(req.params.id), author: req.session.username!, body: parsed.data.body })
    .returning(["id", "author", "body", "created_at"])
    .executeTakeFirstOrThrow();

  logger.info({ event: "host.comment_added", host_id: req.params.id, added_by: req.session.username });
  recordAudit("host.comment_added", req.session.username, req.ip, { host_id: req.params.id });

  res.status(201).json(comment);
}));

// Admin-only, not requireOperator: deleting someone else's comment is a
// moderation action, not the day-to-day host annotation that operators
// are otherwise allowed to do (add tags/comments, rescan).
hostsRouter.delete("/:id/comments/:commentId", requireAdmin, asyncHandler(async (req, res) => {
  const result = await db
    .deleteFrom("host_comments")
    .where("host_id", "=", req.params.id)
    .where("id", "=", req.params.commentId)
    .executeTakeFirst();

  if (result.numDeletedRows === 0n) {
    res.status(404).json({ error: "comment not found" });
    return;
  }

  logger.info({
    event: "host.comment_deleted",
    host_id: req.params.id,
    comment_id: req.params.commentId,
    deleted_by: req.session.username,
  });
  recordAudit("host.comment_deleted", req.session.username, req.ip, {
    host_id: req.params.id,
    comment_id: req.params.commentId,
  });

  res.status(204).end();
}));

// Admin-only, same tier as revoking/deleting a scanner agent - unlike
// retention's automated sweep (age-based, no operator judgment involved),
// this is a deliberate one-off removal of a specific host and everything
// tied to it, so it gets the same access level as every other hard,
// irreversible delete in this codebase. Cascades through
// host_port_observations/screenshots/rdp_screenshots/tls_certificates/
// ssh_host_keys/host_tags/host_comments exactly like retention.ts's own
// deleteFrom("hosts") does (ON DELETE CASCADE on every one of those
// foreign keys); scan_requests.host_id is ON DELETE SET NULL, so any
// still-queued request for this host survives with the reference cleared
// rather than vanishing.
hostsRouter.delete("/:id", requireAdmin, asyncHandler(async (req, res) => {
  if (!uuidSchema.safeParse(req.params.id).success) {
    res.status(400).json({ error: "invalid host id" });
    return;
  }

  const result = await db.deleteFrom("hosts").where("id", "=", req.params.id).returning(["ip"]).executeTakeFirst();

  if (!result) {
    res.status(404).json({ error: "host not found" });
    return;
  }

  logger.info({ event: "host.deleted", host_id: req.params.id, ip: result.ip, deleted_by: req.session.username, source_ip: req.ip });
  recordAudit("host.deleted", req.session.username, req.ip, { host_id: req.params.id, ip: result.ip });

  res.status(204).end();
}));
