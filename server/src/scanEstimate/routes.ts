import { sql } from "kysely";
import { Router, type Request } from "express";
import { z } from "zod";
import { targetSpecSchema } from "../lib/targetSpec";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { MAX_SPLIT_SCANNERS, partRate, splitTargetSpec } from "../lib/scanSplit";
import { DEFAULT_MASSCAN_RATE, estimateScan, projectEnrichment, type EnrichmentProjection, type ScanEstimate } from "./estimate";
import { expandTargetPattern } from "../lib/targetPattern";
import { udpProbesInScope } from "../lib/udpProbes";

export const scanEstimateRouter = Router();
scanEstimateRouter.use(requireAuth);

const estimateSchema = z.object({
  targetSpec: targetSpecSchema,
  portSpec: z.string().trim().min(1),
  scannerAgentId: z.string().uuid().optional(),
  // Several scanners: the estimate is per part, and the scan takes as
  // long as its slowest part.
  scannerAgentIds: z.array(z.string().uuid()).min(1).max(MAX_SPLIT_SCANNERS).optional(),
  // The per-scan rate override, if the form has one filled in - so the
  // estimate reflects the scan actually about to be queued, not a
  // different one.
  masscanRate: z.number().int().min(1).optional(),
  masscanRateSplit: z.boolean().optional(),
});

// The rate a scanner would really use when no per-scan override is set:
// its dashboard override, otherwise what it reported from its own
// config.yaml, otherwise masscan's default. An estimate against a rate the
// scan will not run at is worse than none. Scanner-scoped, so a restricted
// session cannot learn another scanner's configured rate through this.
async function configuredRates(req: Request, ids: string[]): Promise<Map<string, number>> {
  if (ids.length === 0) return new Map();
  const allowed = getAllowedScannerAgentIds(req);
  let query = db.selectFrom("scanner_agents").select(["id", "base_config", "config_overrides"]).where("id", "in", ids);
  if (allowed) query = query.where("id", "in", allowed);
  const out = new Map<string, number>();
  for (const agent of await query.execute()) {
    const configured = agent.config_overrides?.masscanRate ?? agent.base_config?.masscanRate;
    if (typeof configured === "number" && configured > 0) out.set(agent.id, configured);
  }
  return out;
}

function rateFor(id: string | undefined, override: number | undefined, configured: Map<string, number>) {
  if (override) return { rate: override, rateSource: "override" as const };
  const c = id ? configured.get(id) : undefined;
  return c ? { rate: c, rateSource: "scanner" as const } : { rate: DEFAULT_MASSCAN_RATE, rateSource: "default" as const };
}

// The scanner's completed scans of the last 30 days, newest first, for
// projectEnrichment. Capped: a projection needs a sample, not every scan.
async function pastScans(scannerAgentId: string) {
  const rows = await db
    .selectFrom("scan_jobs")
    .select([
      "target_spec",
      "port_spec",
      "started_at",
      "finished_at",
      sql<string>`(select count(distinct host_id) from host_port_observations where scan_job_id = scan_jobs.id)`.as("hosts"),
    ])
    .where("scanner_agent_id", "=", scannerAgentId)
    .where("status", "=", "completed")
    .where("finished_at", "is not", null)
    .where("started_at", ">=", new Date(Date.now() - 30 * 86_400_000))
    .orderBy("started_at", "desc")
    .limit(100)
    .execute();
  return rows.map((r) => ({
    targetSpec: r.target_spec,
    portSpec: r.port_spec,
    durationSeconds: (r.finished_at!.getTime() - r.started_at.getTime()) / 1000,
    hostsScanned: Number(r.hosts),
  }));
}

interface ExcludeSummary {
  ips: number;
  ipPatterns: number;
  ipPorts: number;
  ports: number;
  // The excluded ports themselves - admin only, like every other view of
  // the exclude list (see /api/scan-jobs/active's applicable_excludes).
  portValues?: string[];
}

// The excludes the scanner will fetch for this scan: the global ones plus
// any scoped to the chosen scanner(s), the same union GET
// /api/ingest/excludes serves.
async function excludeSummary(ids: string[], isAdmin: boolean): Promise<ExcludeSummary> {
  const rows = await db
    .selectFrom("scan_excludes")
    .select(["kind", "value"])
    .where((eb) => (ids.length > 0 ? eb.or([eb("scanner_agent_id", "is", null), eb("scanner_agent_id", "in", ids)]) : eb("scanner_agent_id", "is", null)))
    .execute();
  const count = (kind: string) => rows.filter((r) => r.kind === kind).length;
  const summary: ExcludeSummary = { ips: count("ip"), ipPatterns: count("ip_pattern"), ipPorts: count("ip_port"), ports: count("port") };
  if (isAdmin) summary.portValues = [...new Set(rows.filter((r) => r.kind === "port").map((r) => r.value))].sort();
  return summary;
}

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

  // A pattern is estimated as what it expands to - the list the scanner
  // will actually run - and a pattern that does not expand is refused
  // with the same reason queueing it would give.
  const expansion = expandTargetPattern(parsed.data.targetSpec);
  if (!expansion.ok) {
    res.status(400).json({ error: expansion.error });
    return;
  }
  const targetSpec = expansion.expanded ? expansion.spec : parsed.data.targetSpec;

  const ids = [...new Set(parsed.data.scannerAgentIds ?? (parsed.data.scannerAgentId ? [parsed.data.scannerAgentId] : []))];
  const configured = await configuredRates(req, ids);
  const whole = rateFor(ids[0], parsed.data.masscanRate, configured);
  const estimate: ScanEstimate & {
    parts?: Array<ScanEstimate & { scannerAgentId: string; targetSpec: string }>;
    splitError?: string;
    expandedFrom?: string;
    udpProbes?: Array<{ port: number; label: string }>;
    excludes?: ExcludeSummary;
    enrichment?: EnrichmentProjection | null;
  } = estimateScan(targetSpec, parsed.data.portSpec, whole.rate, whole.rateSource);

  if (ids.length > 1) {
    const split = splitTargetSpec(targetSpec, ids);
    if (!split.ok) {
      estimate.splitError = split.error;
    } else {
      estimate.parts = split.parts.map((p) => {
        const r = rateFor(p.scannerAgentId, parsed.data.masscanRate, configured);
        const rate = r.rateSource === "override" ? partRate(r.rate, split.parts.length, parsed.data.masscanRateSplit ?? false)! : r.rate;
        return { scannerAgentId: p.scannerAgentId, targetSpec: p.targetSpec, ...estimateScan(p.targetSpec, parsed.data.portSpec, rate, r.rateSource) };
      });
    }
  }

  if (expansion.expanded) estimate.expandedFrom = parsed.data.targetSpec;
  // What the scan will actually do beyond the discovery pass, so the
  // estimate answers the same questions the scanner's --dry-run does.
  estimate.udpProbes = udpProbesInScope(parsed.data.portSpec);
  // Scoped like the rates above: a restricted session never learns about
  // excludes on a scanner it is not assigned to.
  const allowed = getAllowedScannerAgentIds(req);
  const visibleIds = allowed ? ids.filter((id) => allowed.includes(id)) : ids;
  estimate.excludes = await excludeSummary(visibleIds, req.session.role === "admin");
  // The rest of the scan, from this scanner's own history. For a split
  // scan, the first scanner's history stands for all - the parts run in
  // parallel on similar hardware, and the table above already shows how
  // the addresses divide.
  if (estimate.addresses !== null && visibleIds.length > 0) {
    estimate.enrichment = projectEnrichment(await pastScans(visibleIds[0]), estimate.addresses, whole.rate);
  }
  res.json(estimate);
}));
