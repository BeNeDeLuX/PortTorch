import fs from "fs";
import path from "path";
import { Router } from "express";
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

  let webQuery = db
    .selectFrom("screenshots")
    .innerJoin("hosts", "hosts.id", "screenshots.host_id")
    .select([
      "screenshots.id as id",
      "screenshots.host_id as host_id",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
      "screenshots.port as port",
      "screenshots.url as url",
      "screenshots.page_title as page_title",
      "screenshots.http_status as http_status",
      "screenshots.captured_at as captured_at",
    ]);
  let rdpQuery = db
    .selectFrom("rdp_screenshots")
    .innerJoin("hosts", "hosts.id", "rdp_screenshots.host_id")
    .select([
      "rdp_screenshots.id as id",
      "rdp_screenshots.host_id as host_id",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
      "rdp_screenshots.port as port",
      "rdp_screenshots.captured_at as captured_at",
    ]);

  if (allowed) {
    webQuery = webQuery.where("hosts.scanner_agent_id", "in", allowed);
    rdpQuery = rdpQuery.where("hosts.scanner_agent_id", "in", allowed);
  }

  const [web, rdp] = await Promise.all([
    webQuery
      .distinctOn(["screenshots.host_id", "screenshots.port"])
      .orderBy("screenshots.host_id")
      .orderBy("screenshots.port")
      .orderBy("screenshots.captured_at", "desc")
      .execute(),
    rdpQuery
      .distinctOn(["rdp_screenshots.host_id", "rdp_screenshots.port"])
      .orderBy("rdp_screenshots.host_id")
      .orderBy("rdp_screenshots.port")
      .orderBy("rdp_screenshots.captured_at", "desc")
      .execute(),
  ]);

  const items = [
    ...web.map((s) => ({ ...s, kind: "web" as const })),
    ...rdp.map((s) => ({ ...s, url: null, page_title: null, http_status: null, kind: "rdp" as const })),
  ];

  // Newest first: the point of the page is a quick look at what is out
  // there now, so anything just discovered belongs at the top.
  items.sort((a, b) => new Date(b.captured_at).getTime() - new Date(a.captured_at).getTime());

  res.json(items);
}));

screenshotsRouter.get("/:id/image", serveImage("screenshots"));

export const rdpScreenshotsRouter = Router();
rdpScreenshotsRouter.use(requireAuth);
rdpScreenshotsRouter.get("/:id/image", serveImage("rdp_screenshots"));
