// Shared by Dashboard's active-scans banner and the Scanner Agents page's
// per-agent status, so "running for Xm Ys" is worded identically in both.
export function elapsedLabel(startedAt: string): string {
  return durationLabel(Math.max(0, Date.now() - new Date(startedAt).getTime()));
}

// Same Xm Ys shape as elapsedLabel, but for a known fixed duration (Scan
// History's duration_ms) rather than one computed against the current
// time.
export function durationLabel(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}
