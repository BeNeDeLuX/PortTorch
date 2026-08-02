import { db } from "./db";

export type ScanCancelOutcome = { ok: true } | { ok: false; status: number; error: string };

// Shared by the dashboard's per-job "Stop" button (scanJobs/routes.ts)
// and the external API's host-based cancel (integrations/routes.ts) -
// both just need "flag this specific, currently cancellable, running
// scan_job for cancellation" once they've each resolved which job_id
// that is (the dashboard already has it; the external API resolves it
// from a host lookup first). Re-checks cancellable/running/not-already-
// requested here rather than trusting either caller.
export async function requestScanCancel(scanJobId: string): Promise<ScanCancelOutcome> {
  const result = await db
    .updateTable("scan_jobs")
    .set({ cancel_requested_at: new Date().toISOString() })
    .where("id", "=", scanJobId)
    .where("status", "=", "running")
    .where("cancellable", "=", true)
    .where("cancel_requested_at", "is", null)
    .executeTakeFirst();

  if (result.numUpdatedRows === 0n) {
    return {
      ok: false,
      status: 409,
      error: "scan job is not a cancellable running job, or cancellation was already requested",
    };
  }
  return { ok: true };
}
