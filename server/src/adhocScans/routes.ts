import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";
import { ScanProfileNotFoundError, resolveNSEProfile } from "../scanProfiles/resolve";
import { NucleiProfileNotFoundError, resolveNucleiProfile } from "../nucleiProfiles/resolve";

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

const createAdhocScanSchema = z.object({
  scannerAgentId: z.string().uuid(),
  targetSpec: z.string().trim().min(1),
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
  profile: nseProfileSelectionSchema.optional(),
  nucleiProfile: nucleiProfileSelectionSchema.optional(),
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
    const allowed = getAllowedScannerAgentIds(req);
    if (allowed && !allowed.includes(parsed.data.scannerAgentId)) {
      res.status(403).json({ error: "not allowed to use this scanner agent" });
      return;
    }

    const agent = await db
      .selectFrom("scanner_agents")
      .select(["id", "name"])
      .where("id", "=", parsed.data.scannerAgentId)
      .executeTakeFirst();
    if (!agent) {
      res.status(400).json({ error: "unknown scanner agent" });
      return;
    }

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

    const request = await db
      .insertInto("scan_requests")
      .values({
        scanner_agent_id: parsed.data.scannerAgentId,
        host_id: null,
        target_spec: parsed.data.targetSpec,
        port_spec: parsed.data.portSpec,
        requested_by: req.session.username,
        nse_profile: resolvedProfile.nseProfile,
        nse_scripts: resolvedProfile.nseScripts,
        nse_profile_label: resolvedProfile.nseProfileLabel,
        nuclei_profile: resolvedNucleiProfile.nucleiProfile,
        nuclei_tags: resolvedNucleiProfile.nucleiTags,
        nuclei_profile_label: resolvedNucleiProfile.nucleiProfileLabel,
      })
      .returning(["id", "created_at", "nse_profile_label", "nuclei_profile_label"])
      .executeTakeFirstOrThrow();

    logger.info({
      event: "adhoc_scan.requested",
      scan_request_id: request.id,
      scanner_agent_id: parsed.data.scannerAgentId,
      scanner_agent_name: agent.name,
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
      requested_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("adhoc_scan.requested", req.session.username, req.ip, {
      scan_request_id: request.id,
      scanner_agent_id: parsed.data.scannerAgentId,
      scanner_agent_name: agent.name,
      target_spec: parsed.data.targetSpec,
      port_spec: parsed.data.portSpec,
    });

    res.status(201).json({ ...request, scannerAgentName: agent.name });
  })
);
