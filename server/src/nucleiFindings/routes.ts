import { Router } from "express";
import { sql } from "kysely";
import { db } from "../db";
import { requireAuth } from "../auth/middleware";
import { getAllowedScannerAgentIds } from "../auth/scannerScope";
import { asyncHandler } from "../lib/asyncHandler";

export const nucleiFindingsRouter = Router();
nucleiFindingsRouter.use(requireAuth);

// Fleet-wide view across all hosts, own page rather than folded into
// /api/vulnerabilities - nuclei's template-id/severity/tags shape doesn't
// map onto that route's CVE/CPE/CVSS/EPSS/KEV columns at all (see
// CLAUDE.md's nuclei section). Same "most recent per identity" dedup as
// the per-host list in search/routes.ts - identity here is
// (host_id, template_id, matched_at) since the same template can match
// multiple URLs/paths on the same host, and a rescan re-observing the same
// finding shouldn't show up twice.
nucleiFindingsRouter.get("/", asyncHandler(async (req, res) => {
  const allowed = getAllowedScannerAgentIds(req);
  let query = db
    .selectFrom("nuclei_findings")
    .innerJoin("hosts", "hosts.id", "nuclei_findings.host_id")
    // Left join: an untriaged finding (the normal case - only deliberate
    // exceptions get a finding_triage row) still comes back, with a null
    // state meaning "open". Keyed on the same (host, template, matched_at)
    // identity this query already dedups on.
    .leftJoin("finding_triage", (join) =>
      join
        .onRef("finding_triage.host_id", "=", "nuclei_findings.host_id")
        .onRef("finding_triage.template_id", "=", "nuclei_findings.template_id")
        .onRef("finding_triage.matched_at", "=", "nuclei_findings.matched_at")
        .on("finding_triage.kind", "=", "nuclei")
    )
    // The fleet-wide fallback, applied only where no per-host decision
    // exists (see the coalesce below) - the specific beats the general.
    .leftJoin("finding_triage_rules", (join) =>
      join
        .onRef("finding_triage_rules.template_id", "=", "nuclei_findings.template_id")
        .on("finding_triage_rules.kind", "=", "nuclei")
    )
    .select([
      "nuclei_findings.id as id",
      "hosts.id as host_id",
      "hosts.ip as host_ip",
      "hosts.hostname as host_hostname",
      "nuclei_findings.port as port",
      "nuclei_findings.template_id as template_id",
      "nuclei_findings.name as name",
      "nuclei_findings.severity as severity",
      "nuclei_findings.matched_at as matched_at",
      "nuclei_findings.description as description",
      "nuclei_findings.reference as reference",
      "nuclei_findings.tags as tags",
      "nuclei_findings.curl_command as curl_command",
      "nuclei_findings.observed_at as observed_at",
      sql<string | null>`coalesce(finding_triage.state, finding_triage_rules.state)`.as("triage_state"),
      sql<string | null>`coalesce(finding_triage.note, finding_triage_rules.note)`.as("triage_note"),
      "finding_triage.review_at as triage_review_at",
      sql<boolean | null>`(finding_triage.review_at IS NOT NULL AND finding_triage.review_at <= now())`.as("triage_expired"),
      // So the UI can say a finding is dismissed fleet-wide rather than
      // presenting it as a decision someone made about this host.
      sql<boolean | null>`(finding_triage.state IS NULL AND finding_triage_rules.state IS NOT NULL)`.as("triage_from_rule"),
    ])
    .distinctOn(["nuclei_findings.host_id", "nuclei_findings.template_id", "nuclei_findings.matched_at"])
    .orderBy("nuclei_findings.host_id")
    .orderBy("nuclei_findings.template_id")
    .orderBy("nuclei_findings.matched_at")
    .orderBy("nuclei_findings.observed_at", "desc");

  if (allowed) {
    query = query.where("hosts.scanner_agent_id", "in", allowed);
  }

  const rows = await query.execute();
  res.json(rows);
}));
