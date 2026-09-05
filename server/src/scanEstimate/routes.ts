import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { DEFAULT_MASSCAN_RATE, estimateScan } from "./estimate";

export const scanEstimateRouter = Router();
scanEstimateRouter.use(requireAuth);

const estimateSchema = z.object({
  targetSpec: z.string().trim().min(1),
  portSpec: z.string().trim().min(1),
  scannerAgentId: z.string().uuid().optional(),
  // The per-scan rate override, if the form has one filled in - so the
  // estimate reflects the scan actually about to be queued, not a
  // different one.
  masscanRate: z.number().int().min(1).optional(),
});

// Same access level as the Ad-hoc Scans form it sits in - anyone who can
// see that form can ask what a scan would cost, which is strictly less
// than being able to start one. Read-only: it computes, it stores
// nothing and queues nothing.
scanEstimateRouter.post("/", asyncHandler(async (req, res) => {
  const parsed = estimateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  // The rate the *chosen* scanner would really use: a dashboard override
  // if one is set for it, otherwise what it reported from its own
  // config.yaml, otherwise masscan's default. An estimate against a rate
  // the scan will not run at is worse than none.
  let rate = DEFAULT_MASSCAN_RATE;
  let rateSource: "override" | "scanner" | "default" = "default";
  if (parsed.data.masscanRate) {
    rate = parsed.data.masscanRate;
    rateSource = "override";
  } else if (parsed.data.scannerAgentId) {
    const allowed = getAllowedScannerAgentIds(req);
    let query = db
      .selectFrom("scanner_agents")
      .select(["base_config", "config_overrides"])
      .where("id", "=", parsed.data.scannerAgentId);
    if (allowed) {
      query = query.where("id", "in", allowed);
    }
    const agent = await query.executeTakeFirst();
    const configured = agent?.config_overrides?.masscanRate ?? agent?.base_config?.masscanRate;
    if (typeof configured === "number" && configured > 0) {
      rate = configured;
      rateSource = "scanner";
    }
  }

  res.json(estimateScan(parsed.data.targetSpec, parsed.data.portSpec, rate, rateSource));
}));
