import { db } from "../db";

export type RequestTemplateUpdateOutcome = { ok: true } | { ok: false; status: number; error: string };

// Mirrors requestUpdate.ts's requestScannerUpdate exactly, against the
// template_update_* columns instead - same compare-and-set shape, same
// reason it has to be a polled flag rather than a push (see CLAUDE.md's
// "Why two separate services"). The scanner's own template-update watcher
// picks it up on its next tick (GET /api/ingest/template-update-requested).
//
// Deliberately independent of an outstanding *binary* self-update: both
// can be requested at once, and neither blocks the other, since the two
// touch entirely separate things on the scanner host (the porttorch
// binary vs. the nuclei template tree in the service user's home).
export async function requestTemplateUpdate(agentId: string): Promise<RequestTemplateUpdateOutcome> {
  const result = await db
    .updateTable("scanner_agents")
    .set({
      template_update_requested_at: new Date(),
      template_update_status: "pending",
      template_update_attempt_count: 0,
      template_update_failure_reason: null,
    })
    .where("id", "=", agentId)
    .where("revoked_at", "is", null)
    // "Is one already outstanding" keys on the status, not on
    // requested_at being null the way requestScannerUpdate does - see the
    // note in ingest/routes.ts's /template-update-outcome: requested_at is
    // deliberately kept after a give-up (as the anchor the opportunistic
    // clear compares a reported template age against), so it can't double
    // as the "nothing outstanding" guard here. 'failed' is re-triggerable,
    // 'pending' is not.
    .where((eb) => eb.or([eb("template_update_status", "is", null), eb("template_update_status", "=", "failed")]))
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    return {
      ok: false,
      status: 409,
      error: "scanner agent not found, revoked, or a template update was already requested",
    };
  }
  return { ok: true };
}
