import { Router } from "express";
import { z } from "zod";
import { targetSpecSchema } from "../lib/targetSpec";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { ScanProfileNotFoundError, resolveNSEProfile } from "../scanProfiles/resolve";
import { NucleiProfileNotFoundError, resolveNucleiProfile } from "../nucleiProfiles/resolve";
import { DEFAULT_SCAN_PRIORITY, scanPrioritySchema } from "../scanPriority";
import { normalizeScanTags, scanTagsSchema } from "../lib/scanTags";
import { queueScan } from "../scanGroups/queue";
import { MAX_SPLIT_SCANNERS } from "../lib/scanSplit";

// A one-shot scan against an arbitrary target - the same NSE/nuclei
// profile choice Schedule Scans offers, minus all scheduling (no
// interval/cron/run-at, no persistent scan_schedules row at all). Creates
// a scan_requests row directly, structurally identical to what
// scheduler.ts's tick() inserts when firing a schedule - the target
// scanner picks it up on its very next poll, same queue as everything
// else. requireOperator (not requireAdmin like Schedules) since this is a
// one-shot operational action, not persistent config - same access tier
// as the Rescan button.
export const adhocScansRouter = Router();
adhocScansRouter.use(requireAuth);

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

const createAdhocScanSchema = z
  .object({
  // One scanner, as before - or several, to split the target between
  // them (lib/scanSplit.ts). Either is accepted; the External API and any
  // caller written before splitting existed keep sending scannerAgentId.
  scannerAgentId: z.string().uuid().optional(),
  scannerAgentIds: z.array(z.string().uuid()).min(1).max(MAX_SPLIT_SCANNERS).optional(),
  // With several scanners, masscanRate is the total for the whole scan
  // and is divided between them, so splitting cuts the runtime without
  // multiplying the packets per second the target network sees.
  masscanRateSplit: z.boolean().optional(),
  targetSpec: targetSpecSchema,
  // No format validation beyond non-empty - unlike scan_excludes (which
  // the webserver itself enforces against), a scan target is only ever
  // interpreted by the scanner. That includes a plain DNS hostname now.
  // masscan's own IPv4/CIDR/range grammar and the scanner's own IPv6
  // single/list handling both still work exactly as before; a hostname
  // target is resolved scanner-side (see the root CLAUDE.md - only the
  // scanner can correctly resolve an internal-only/split-horizon name)
  // and automatically becomes the TLS SNI/screenshot hostname too, no
  // separate field needed.
  portSpec: z.string().trim().min(1),
  // Optional per-scan override of the scanner's own configured
  // masscanRate - omitted/null means the scanner keeps using its config
  // value, so this never changes behavior for anyone who doesn't set it.
  masscanRate: z.number().int().min(1).max(10_000_000).optional(),
  profile: nseProfileSelectionSchema.optional(),
  nucleiProfile: nucleiProfileSelectionSchema.optional(),
  // Where this lands in the scanner's claim order (see src/scanPriority.ts).
  // Omitted defaults to 'normal' rather than 'high' so the External API's
  // own ad-hoc endpoint keeps behaving exactly as before this column
  // existed - the dashboard's form is what pre-selects 'high', since an
  // operator typing a target into it is by definition waiting on it.
  priority: scanPrioritySchema.optional(),
  // Optional - applied to every host this scan actually touches once
  // ingest sees it (ingest/routes.ts's ingestHostPayload), so "find
  // exactly what this scan found" is a tag filter afterwards rather than
  // re-deriving it from the target spec. See lib/scanTags.ts.
  tags: scanTagsSchema,
  })
  .refine((d) => d.scannerAgentId || (d.scannerAgentIds && d.scannerAgentIds.length > 0), {
    message: "pick at least one scanner",
  })
  .refine((d) => !d.masscanRateSplit || d.masscanRate !== undefined, {
    message: "dividing the rate between scanners needs a rate to divide",
  });

adhocScansRouter.post(
  "/",
  requireOperator,
  asyncHandler(async (req, res) => {
    const parsed = createAdhocScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    // A restricted operator/user (see CLAUDE.md's "Roles and permissions")
    // could otherwise fire a scan against a scanner they're not supposed
    // to have access to at all - unlike Schedule creation (requireAdmin
    // only, and admins are always unrestricted), this route is reachable
    // by restricted accounts, so the pick needs the same check every
    // fleet-wide read endpoint already applies.
    const scannerAgentIds = [...new Set(parsed.data.scannerAgentIds ?? [parsed.data.scannerAgentId!])];
    const allowed = getAllowedScannerAgentIds(req);
    if (allowed && scannerAgentIds.some((id) => !allowed.includes(id))) {
      res.status(403).json({ error: "not allowed to use this scanner agent" });
      return;
    }

    const agents = await db
      .selectFrom("scanner_agents")
      .select(["id", "name", "revoked_at"])
      .where("id", "in", scannerAgentIds)
      .execute();
    if (agents.length !== scannerAgentIds.length) {
      res.status(400).json({ error: "unknown scanner agent" });
      return;
    }
    // A revoked scanner can never claim its share, so that part of the
    // target would silently never be scanned.
    if (scannerAgentIds.length > 1 && agents.some((a) => a.revoked_at)) {
      res.status(400).json({ error: "a revoked scanner cannot take part in a split scan" });
      return;
    }
    const agentName = new Map(agents.map((a) => [a.id, a.name]));

    let resolvedProfile;
    try {
      resolvedProfile = await resolveNSEProfile(parsed.data.profile ?? { kind: "default" });
    } catch (err) {
      if (err instanceof ScanProfileNotFoundError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }

    let resolvedNucleiProfile;
    try {
      resolvedNucleiProfile = await resolveNucleiProfile(parsed.data.nucleiProfile ?? { kind: "off" });
    } catch (err) {
      if (err instanceof NucleiProfileNotFoundError) {
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }

    const priority = parsed.data.priority ?? DEFAULT_SCAN_PRIORITY;
    const tags = normalizeScanTags(parsed.data.tags);
    const queued = await db.transaction().execute((trx) =>
      queueScan(
        trx,
        parsed.data.targetSpec,
        scannerAgentIds,
        {
          port_spec: parsed.data.portSpec,
          requested_by: req.session.username ?? null,
          nse_profile: resolvedProfile.nseProfile,
          nse_scripts: resolvedProfile.nseScripts,
          nse_profile_label: resolvedProfile.nseProfileLabel,
          nuclei_profile: resolvedNucleiProfile.nucleiProfile,
          nuclei_tags: resolvedNucleiProfile.nucleiTags,
          nuclei_profile_label: resolvedNucleiProfile.nucleiProfileLabel,
          masscan_rate: parsed.data.masscanRate ?? null,
          priority,
          tags,
          schedule_id: null,
        },
        parsed.data.masscanRateSplit ?? false
      )
    );
    if (!queued.ok) {
      res.status(400).json({ error: queued.error });
      return;
    }

    for (const part of queued.parts) {
      logger.info({
        event: "adhoc_scan.requested",
        scan_request_id: part.id,
        scan_group_id: queued.groupId,
        scanner_agent_id: part.scannerAgentId,
        scanner_agent_name: agentName.get(part.scannerAgentId),
        target_spec: part.targetSpec,
        port_spec: parsed.data.portSpec,
        masscan_rate: part.masscanRate,
        priority,
        tags,
        requested_by: req.session.username,
        source_ip: req.ip,
      });
    }
    recordAudit("adhoc_scan.requested", req.session.username, req.ip, {
      scan_request_id: queued.parts[0].id,
      scan_group_id: queued.groupId,
      scanner_agent_ids: queued.parts.map((p) => p.scannerAgentId),
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
      tags,
    });

    // The first part's fields at the top level keep the response shape
    // every caller written before splitting existed reads; `parts` is the
    // whole picture.
    const first = queued.parts[0];
    res.status(201).json({
      id: first.id,
      created_at: new Date().toISOString(),
      nse_profile_label: resolvedProfile.nseProfileLabel,
      nuclei_profile_label: resolvedNucleiProfile.nucleiProfileLabel,
      priority,
      tags,
      scannerAgentName: agentName.get(first.scannerAgentId),
      scanGroupId: queued.groupId,
      parts: queued.parts.map((p) => ({ ...p, scannerAgentName: agentName.get(p.scannerAgentId) })),
    });
  })
);
