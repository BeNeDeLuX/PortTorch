// Shared by scanJobs/routes.ts (scan_jobs stuck in "running", e.g. a
// scanner process that died mid-scan) and search/routes.ts (scan_requests
// stuck in "pending"/"claimed", e.g. the target scanner is offline or
// died after claiming) - both are "last update timestamp is too old for
// this to still be legitimately in progress" checks against the same
// admin-configurable threshold (app_settings.stale_scan_threshold_minutes,
// see settings/appSettings.ts - callers fetch it themselves rather than
// this module reaching into the DB, so a request handler only pays for
// one settings read even when it calls this multiple times), just against
// different timestamp fields.
export function isStale(referenceTime: Date | string, thresholdMinutes: number): boolean {
  return Date.now() - new Date(referenceTime).getTime() > thresholdMinutes * 60_000;
}

// A running scan_jobs row's own "last known good" timestamp isn't just
// when it started - the scanner's progress.Tracker pushes a heartbeat
// snapshot to scan_job_progress every ~3s for as long as the process is
// alive (scanner/internal/progress/tracker.go's DefaultPushInterval),
// regardless of whether anything genuinely new happened in that window.
// Using only started_at meant a scan that's simply slow - e.g. masscan's
// own single, unstreamable pass across a large target range, which can
// legitimately take well over an hour before nmap (and real per-host
// activity) even begins - got flagged stale despite the scanner process
// being demonstrably alive and progressing. Falls back to startedAt when
// there's no progress row yet (e.g. the very first tick, before the
// scanner's first push has landed) - still correct for that case, since
// there's no more recent signal to prefer. A genuinely dead scanner
// process's Tracker goroutine dies with it, so the last progress push
// stops updating and this still correctly goes stale once that heartbeat
// has actually been silent past the threshold.
export function isStaleScanJob(
  startedAt: Date | string,
  lastProgressAt: Date | string | null,
  thresholdMinutes: number
): boolean {
  return isStale(lastProgressAt ?? startedAt, thresholdMinutes);
}
