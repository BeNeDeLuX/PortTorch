// Plain X.Y.Z numeric compare - no pre-release/build-metadata handling,
// since neither this project's version.go nor its scanner-vX.Y.Z release
// tags ever use one.
//
// The webserver and the Go scanner keep their own copies of this (see
// scannerUpdate/githubSync.ts and internal/updater) - deliberately, since
// sharing across a language boundary isn't worth the coupling. Within the
// frontend, though, it lives here once: useFleetHealth.ts and
// ScannerAgents.tsx had grown two independent copies, and a third was
// about to be added for the scan-rate capability check below, which is
// where "it's a tiny self-contained function" stops being a good reason.
export function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

export function isVersionBehind(current: string | null, latest: string | null): boolean {
  if (!current || !latest) return false;
  return compareSemver(latest, current) > 0;
}
