import { Router } from "express";
import { z } from "zod";
import { db } from "../db";
import { requireAuth, requireOperator } from "../auth/middleware";
import { asyncHandler } from "../lib/asyncHandler";
import { logger } from "../logger";
import { recordAudit } from "../audit/log";

// Marking a finding a false positive / accepted risk / fixed, so it stops
// competing for attention on the Vulnerabilities and Web Findings pages
// after every scan. requireOperator, matching host tags/comments/rescan -
// this is day-to-day analyst annotation, not persistent config, and it
// never deletes or hides underlying scan data (the finding itself is
// untouched; only its display state changes, and the pages can still show
// triaged findings on demand).
export const findingTriageRouter = Router();
findingTriageRouter.use(requireAuth);

const TRIAGE_STATES = ["false_positive", "accepted_risk", "fixed"] as const;

// A discriminated union rather than one flat object with everything
// optional, so "kind: cve with a template_id" can't typecheck its way to
// the database and get rejected by the table's own CHECK constraint.
const identitySchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("cve"), hostId: z.string().uuid(), cveId: z.string().min(1) }),
  z.object({
    kind: z.literal("nuclei"),
    hostId: z.string().uuid(),
    templateId: z.string().min(1),
    matchedAt: z.string().min(1),
  }),
]);

const setTriageSchema = z.intersection(
  identitySchema,
  z.object({
    state: z.enum(TRIAGE_STATES),
    note: z.string().trim().max(2000).optional(),
    // ISO timestamp after which this decision stops applying and the
    // finding resurfaces. Omitted/null = never expires. Accepting a risk
    // indefinitely is the exception, not the rule - see the review_at
    // migration - but it stays possible, so this isn't required.
    reviewAt: z.string().datetime().nullable().optional(),
  })
);

const clearTriageSchema = identitySchema;

// Upsert, not insert - re-triaging an already-triaged finding (e.g.
// "accepted risk" that's since actually been fixed) is the normal case,
// not a conflict. onConflict targets the same partial unique indexes the
// migration defines, so the two kinds can't collide with each other.
findingTriageRouter.put(
  "/",
  requireOperator,
  asyncHandler(async (req, res) => {
    const parsed = setTriageSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const input = parsed.data;

    const host = await db.selectFrom("hosts").select(["id"]).where("id", "=", input.hostId).executeTakeFirst();
    if (!host) {
      res.status(404).json({ error: "host not found" });
      return;
    }

    const values = {
      kind: input.kind,
      host_id: input.hostId,
      cve_id: input.kind === "cve" ? input.cveId : null,
      template_id: input.kind === "nuclei" ? input.templateId : null,
      matched_at: input.kind === "nuclei" ? input.matchedAt : null,
      state: input.state,
      note: input.note ?? null,
      review_at: input.reviewAt ?? null,
      created_by: req.session.username ?? null,
    };

    const row = await db
      .insertInto("finding_triage")
      .values(values)
      .onConflict((oc) =>
        oc
          .columns(input.kind === "cve" ? ["host_id", "cve_id"] : ["host_id", "template_id", "matched_at"])
          .where("kind", "=", input.kind)
          .doUpdateSet({
            state: values.state,
            note: values.note,
            // Re-triaging always rewrites the review date, including back
            // to null - otherwise a stale expiry from a previous decision
            // would keep applying to a fresh one.
            review_at: values.review_at,
            created_by: values.created_by,
            updated_at: new Date().toISOString(),
          })
      )
      .returning(["id", "state", "note", "review_at", "updated_at"])
      .executeTakeFirstOrThrow();

    const identity = input.kind === "cve" ? { cve_id: input.cveId } : { template_id: input.templateId, matched_at: input.matchedAt };
    logger.info({
      event: "finding.triaged",
      kind: input.kind,
      host_id: input.hostId,
      ...identity,
      state: input.state,
      review_at: input.reviewAt ?? null,
      triaged_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("finding.triaged", req.session.username, req.ip, {
      kind: input.kind,
      host_id: input.hostId,
      ...identity,
      state: input.state,
    });

    res.json(row);
  })
);

// Back to untriaged - deletes the row rather than storing an explicit
// "open" state, keeping "absence means open" the single source of truth
// (see the migration's own comment).
findingTriageRouter.delete(
  "/",
  requireOperator,
  asyncHandler(async (req, res) => {
    const parsed = clearTriageSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const input = parsed.data;

    let query = db.deleteFrom("finding_triage").where("kind", "=", input.kind).where("host_id", "=", input.hostId);
    query =
      input.kind === "cve"
        ? query.where("cve_id", "=", input.cveId)
        : query.where("template_id", "=", input.templateId).where("matched_at", "=", input.matchedAt);

    const result = await query.executeTakeFirst();
    if (result.numDeletedRows === 0n) {
      res.status(404).json({ error: "no triage state set for this finding" });
      return;
    }

    const identity = input.kind === "cve" ? { cve_id: input.cveId } : { template_id: input.templateId, matched_at: input.matchedAt };
    logger.info({
      event: "finding.triage_cleared",
      kind: input.kind,
      host_id: input.hostId,
      ...identity,
      cleared_by: req.session.username,
      source_ip: req.ip,
    });
    recordAudit("finding.triage_cleared", req.session.username, req.ip, {
      kind: input.kind,
      host_id: input.hostId,
      ...identity,
    });

    res.status(204).end();
  })
);
