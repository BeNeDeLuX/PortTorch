import fs from "fs";
import path from "path";
import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { config } from "../config";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

function serveImage(table: "screenshots" | "rdp_screenshots") {
  return asyncHandler(async (req, res) => {
    const row = await db
      .selectFrom(table)
      .select(["image_path"])
      .where("id", "=", req.params.id)
      .executeTakeFirst();
    if (!row) {
      res.status(404).json({ error: "screenshot not found" });
      return;
    }

    const screenshotRoot = path.resolve(config.screenshotDir);
    const resolved = path.resolve(row.image_path);
    if (resolved !== screenshotRoot && !resolved.startsWith(screenshotRoot + path.sep)) {
      res.status(500).json({ error: "invalid screenshot path" });
      return;
    }
    if (!fs.existsSync(resolved)) {
      res.status(404).json({ error: "screenshot file missing" });
      return;
    }

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "private, max-age=86400");
    fs.createReadStream(resolved).pipe(res);
  });
}

export const screenshotsRouter = Router();
screenshotsRouter.use(requireAuth);

// Fleet-wide gallery: every distinct thing that was ever screenshotted,
// shown once. Not a history - one entry per (host, port, kind), the
// newest capture of each, using the same distinctOn convention the host
// detail page and the certificates list already use.
//
// Identity is host+port rather than host alone, deliberately: a host
// running three web interfaces on three ports has three genuinely
// different screenshots, and collapsing them to one would hide two of
// them. The Dashboard's card view is the one-per-host view.
//
// Registered before "/:id/image" so the bare path isn't swallowed by it.
screenshotsRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);

  // The newest *two* captures per (host, port), so the gallery can say
  // whether the latest one differs from what was there before. A window
  // function rather than two queries: the pairing is the whole point, and
  // doing it in SQL keeps "newest" and "the one before it" from being
  // decided by two different orderings.
  //
  // Raw SQL rather than the query builder because distinctOn cannot
  // express "top 2 per group" - this is the one place in the gallery that
  // needs more than the newest row.
  const scopeFilter = allowed ? sql`and h.scanner_agent_id = any(${allowed}::uuid[])` : sql``;

  const web = await sql<{
    id: string;
    host_id: string;
    host_ip: string;
    host_hostname: string | null;
    port: number;
    url: string | null;
    page_title: string | null;
    http_status: number | null;
    captured_at: Date;
    rn: string;
  }>`
    select s.id, s.host_id, h.ip as host_ip, h.hostname as host_hostname, s.port, s.url,
           s.page_title, s.http_status, s.captured_at,
           row_number() over (partition by s.host_id, s.port order by s.captured_at desc) as rn
    from screenshots s
    join hosts h on h.id = s.host_id
    where true ${scopeFilter}
  `.execute(db);

  const rdp = await sql<{
    id: string;
    host_id: string;
    host_ip: string;
    host_hostname: string | null;
    port: number;
    captured_at: Date;
    rn: string;
  }>`
    select r.id, r.host_id, h.ip as host_ip, h.hostname as host_hostname, r.port, r.captured_at,
           row_number() over (partition by r.host_id, r.port order by r.captured_at desc) as rn
    from rdp_screenshots r
    join hosts h on h.id = r.host_id
    where true ${scopeFilter}
  `.execute(db);

  const items = [
    ...pair(web.rows.map((r) => ({ ...r, kind: "web" as const }))),
    ...pair(
      rdp.rows.map((r) => ({
        ...r,
        url: null as string | null,
        page_title: null as string | null,
        http_status: null as number | null,
        kind: "rdp" as const,
      }))
    ),
  ];

  // Newest first: the point of the page is a quick look at what is out
  // there now, so anything just discovered belongs at the top.
  items.sort((a, b) => new Date(b.captured_at).getTime() - new Date(a.captured_at).getTime());

  res.json(items);
}));

interface RankedCapture {
  id: string;
  host_id: string;
  host_ip: string;
  host_hostname: string | null;
  port: number;
  url: string | null;
  page_title: string | null;
  http_status: number | null;
  captured_at: Date;
  rn: string;
  kind: "web" | "rdp";
}

// Turns the ranked rows into one gallery entry per (host, port): the
// newest capture, plus what the one before it looked like.
//
// "Changed" is decided on the metadata that is actually stored - the page
// title and the HTTP status - never on the images themselves. Two
// captures of the same page are essentially never byte-identical
// (rendering, timestamps on the page, a rotating banner), so an image
// comparison would report a change on almost every scan and be ignored
// within a week. A title going from "Login" to "Index of /" is the signal
// worth surfacing, and it is exact.
function pair(rows: RankedCapture[]) {
  const byKey = new Map<string, { current?: RankedCapture; previous?: RankedCapture }>();
  for (const row of rows) {
    const rank = Number(row.rn);
    if (rank > 2) continue;
    const key = `${row.host_id}:${row.port}`;
    const entry = byKey.get(key) ?? {};
    if (rank === 1) entry.current = row;
    else entry.previous = row;
    byKey.set(key, entry);
  }

  return [...byKey.values()]
    .filter((e): e is { current: RankedCapture; previous?: RankedCapture } => Boolean(e.current))
    .map(({ current, previous }) => ({
      id: current.id,
      host_id: current.host_id,
      host_ip: current.host_ip,
      host_hostname: current.host_hostname,
      port: current.port,
      url: current.url,
      page_title: current.page_title,
      http_status: current.http_status,
      captured_at: current.captured_at,
      kind: current.kind,
      previous: previous
        ? {
            id: previous.id,
            captured_at: previous.captured_at,
            page_title: previous.page_title,
            http_status: previous.http_status,
          }
        : null,
      // A first-ever capture is not a change - there is nothing it
      // differs from, and flagging it would make every new host noisy.
      changed: previous
        ? previous.page_title !== current.page_title || previous.http_status !== current.http_status
        : false,
    }));
}

screenshotsRouter.get("/:id/image", serveImage("screenshots"));

export const rdpScreenshotsRouter = Router();
rdpScreenshotsRouter.use(requireAuth);
rdpScreenshotsRouter.get("/:id/image", serveImage("rdp_screenshots"));
