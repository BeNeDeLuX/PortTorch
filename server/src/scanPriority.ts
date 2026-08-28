import { z } from "zod";
import { sql } from "kysely";

// A scanner claims one pending scan_request per poll, and a "serve"
// scanner's polling loop blocks for the entire duration of whatever it's
// currently running - so a request queued behind a long scheduled sweep
// waits for that whole sweep to finish. Priority is what lets an
// interactive action (an ad-hoc scan someone is sitting there waiting
// for) jump ahead of it, without needing to cancel the sweep.
//
// Stored as text rather than an ordinal smallint, matching every other
// small enum in this schema (nse_profile, nuclei_profile,
// update_request_status) - a human reading scan_requests in psql sees
// 'high', not a 1 they have to look up. The cost is that ordering needs
// the CASE expression below instead of a plain ORDER BY column (the
// three values don't sort correctly alphabetically), which in turn means
// scan_requests_pending_idx can't serve the sort - irrelevant at the size
// a pending queue actually reaches (tens to hundreds of rows for one
// scanner, sorted once per poll interval).
export const SCAN_PRIORITIES = ["high", "normal", "low"] as const;
export type ScanPriority = (typeof SCAN_PRIORITIES)[number];

export const DEFAULT_SCAN_PRIORITY: ScanPriority = "normal";

export const scanPrioritySchema = z.enum(SCAN_PRIORITIES);

// Shared by the scanner's own claim query (ingest/routes.ts) and the
// dashboard's queue view (scanJobs/routes.ts) so the order the queue is
// displayed in can't disagree with the order it's actually consumed in.
// created_at breaks ties, keeping FIFO within a priority level - the
// pre-priority behavior, unchanged for the overwhelmingly common case
// where everything is 'normal'.
export const scanPriorityOrder = sql`CASE priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END`;

export function scanPriorityLabel(priority: string): string {
  switch (priority) {
    case "high":
      return "High";
    case "low":
      return "Low";
    default:
      return "Normal";
  }
}
