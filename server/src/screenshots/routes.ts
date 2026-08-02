import fs from "fs";
import path from "path";
import { Router } from "express";
import { db } from "../db";
import { config } from "../config";
import { requireAuth } from "../auth/middleware";
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
screenshotsRouter.get("/:id/image", serveImage("screenshots"));

export const rdpScreenshotsRouter = Router();
rdpScreenshotsRouter.use(requireAuth);
rdpScreenshotsRouter.get("/:id/image", serveImage("rdp_screenshots"));
