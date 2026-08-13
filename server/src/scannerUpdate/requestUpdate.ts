import { db } from "../db";

export type RequestScannerUpdateOutcome = { ok: true } | { ok: false; status: number; error: string };

// Mirrors scanCancel.ts's requestScanCancel exactly - the webserver can
// never push to a scanner (see CLAUDE.md's "Why two separate services"),
// so this just flags the row for the scanner's own update watcher to
// notice on its next poll (GET /api/ingest/update-requested).
export async function requestScannerUpdate(agentId: string): Promise<RequestScannerUpdateOutcome> {
  const result = await db
    .updateTable("scanner_agents")
    .set({ update_requested_at: new Date(), update_request_status: "pending", update_attempt_count: 0, update_failure_reason: null })
    .where("id", "=", agentId)
    .where("revoked_at", "is", null)
    .where("update_requested_at", "is", null)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    return {
      ok: false,
      status: 409,
      error: "scanner agent not found, revoked, or an update was already requested",
    };
  }
  return { ok: true };
}
