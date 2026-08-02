import { config } from "../config";

// Shared by scanJobs/routes.ts (scan_jobs stuck in "running", e.g. a
// scanner process that died mid-scan) and search/routes.ts (scan_requests
// stuck in "pending"/"claimed", e.g. the target scanner is offline or
// died after claiming) - both are "last update timestamp is too old for
// this to still be legitimately in progress" checks against the same
// configurable threshold, just against different timestamp fields.
export function isStale(referenceTime: Date | string): boolean {
  const thresholdMs = config.staleScanThresholdMinutes * 60_000;
  return Date.now() - new Date(referenceTime).getTime() > thresholdMs;
}
