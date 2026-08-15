import { useEffect, useState } from "react";
import {
  ActiveScanJob,
  api,
  Me,
  QueuedScanRequest,
  ScannerAgent,
  ScannerReleaseInfo,
  TlsCertificateInfo,
} from "../api";
import { certExpiryStatus } from "./certExpiry";

export type HealthStatus = "ok" | "warning" | "critical";

export const STATUS_RANK: Record<HealthStatus, number> = { ok: 0, warning: 1, critical: 2 };
export const STATUS_LABEL: Record<HealthStatus, string> = { ok: "OK", warning: "Warning", critical: "Critical" };

export function worstOf(...statuses: HealthStatus[]): HealthStatus {
  return statuses.reduce((worst, s) => (STATUS_RANK[s] > STATUS_RANK[worst] ? s : worst), "ok" as HealthStatus);
}

// Same plain X.Y.Z compare as ScannerAgents.tsx's own copy (and the
// webserver's/scanner's own compareSemver) - kept as an independent copy
// rather than a shared import since it's a tiny, self-contained function.
function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

function isVersionBehind(current: string | null, latest: string | null): boolean {
  if (!current || !latest) return false;
  return compareSemver(latest, current) > 0;
}

// A queued scan_requests row older than this strongly suggests the
// target scanner has stopped polling entirely, rather than just being
// mid-scan on something else - see CLAUDE.md's "Scan request queue as
// its own view" section. Display-only heuristic, same spirit as
// ScannerAgents.tsx's own RECENTLY_SEEN_THRESHOLD_MS.
export const STALE_QUEUE_THRESHOLD_MS = 30 * 60_000;

export interface FleetHealthData {
  loading: boolean;
  error: boolean;
  overall: HealthStatus;
  scannerStatus: HealthStatus;
  updatesStatus: HealthStatus;
  queueStatus: HealthStatus;
  retryQueueStatus: HealthStatus;
  webserverCertStatus: HealthStatus;
  liveAgents: ScannerAgent[];
  staleJobs: ActiveScanJob[];
  activeScanJobs: ActiveScanJob[];
  behindAgents: ScannerAgent[];
  pendingUpdates: ScannerAgent[];
  failedUpdates: ScannerAgent[];
  latestRelease: ScannerReleaseInfo | null;
  scanQueue: QueuedScanRequest[];
  oldestQueuedMs: number;
  agentsWithRetryBacklog: ScannerAgent[];
  totalRetryQueuePending: number;
  webserverCert: TlsCertificateInfo | null;
}

// Shared by the Fleet Health page itself and the Dashboard's own small
// "needs attention" banner, so the two can never disagree about whether
// something is wrong - same data, same thresholds, computed once. No new
// backend endpoints - everything here is derived from data the Scanner
// Agents/Settings pages already fetch independently.
export function useFleetHealth(me: Me): FleetHealthData {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [latestRelease, setLatestRelease] = useState<ScannerReleaseInfo | null>(null);
  const [activeScanJobs, setActiveScanJobs] = useState<ActiveScanJob[]>([]);
  const [scanQueue, setScanQueue] = useState<QueuedScanRequest[]>([]);
  const [webserverCert, setWebserverCert] = useState<TlsCertificateInfo | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(false);
    Promise.all([
      api.agents(),
      api.latestScannerRelease().catch(() => null),
      me.role === "admin" ? api.tlsCertificate().catch(() => null) : Promise.resolve(null),
    ])
      .then(([a, release, ws]) => {
        setAgents(a);
        setLatestRelease(release);
        setWebserverCert(ws);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
    loadActiveScanJobs();
    loadScanQueue();
    // Same 5s cadence as ScannerAgents.tsx / the Dashboard's own
    // active-scans polling.
    const jobsInterval = setInterval(loadActiveScanJobs, 5000);
    const queueInterval = setInterval(loadScanQueue, 5000);
    return () => {
      clearInterval(jobsInterval);
      clearInterval(queueInterval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadActiveScanJobs() {
    try {
      setActiveScanJobs(await api.activeScanJobs());
    } catch {
      setActiveScanJobs([]);
    }
  }

  async function loadScanQueue() {
    try {
      setScanQueue(await api.scanQueue());
    } catch {
      setScanQueue([]);
    }
  }

  const liveAgents = agents.filter((a) => !a.revoked_at);
  const staleJobs = activeScanJobs.filter((j) => j.is_stale);
  const scannerStatus: HealthStatus = staleJobs.length > 0 ? "critical" : "ok";

  const behindAgents = liveAgents.filter((a) => isVersionBehind(a.version, latestRelease?.latestVersion ?? null));
  const pendingUpdates = liveAgents.filter((a) => a.update_request_status === "pending");
  const failedUpdates = liveAgents.filter((a) => a.update_request_status === "failed");
  const updatesStatus: HealthStatus =
    failedUpdates.length > 0 ? "critical" : behindAgents.length > 0 || pendingUpdates.length > 0 ? "warning" : "ok";

  const oldestQueuedMs =
    scanQueue.length > 0 ? Math.max(...scanQueue.map((q) => Date.now() - new Date(q.created_at).getTime())) : 0;
  const queueStatus: HealthStatus =
    scanQueue.length === 0 ? "ok" : oldestQueuedMs > STALE_QUEUE_THRESHOLD_MS ? "critical" : "warning";

  const webserverCertRawStatus = webserverCert ? certExpiryStatus(webserverCert.validTo) : "ok";
  const webserverCertStatus: HealthStatus =
    webserverCertRawStatus === "expired" ? "critical" : webserverCertRawStatus === "soon" ? "warning" : "ok";

  // The scanner's own internal/submitqueue backlog (host submissions
  // still waiting to be retried after a transient failure) - distinct
  // from the "Scan Queue" card above, which tracks scan_requests rows
  // waiting to be *claimed*, not results waiting to be *resubmitted*.
  // Reported per agent via the same piggyback header as version (see
  // apiKeyAuth.ts) - null (never reported) is treated the same as 0
  // here, since an agent that's never sent the header can't be flagged
  // for a backlog we have no evidence of.
  const agentsWithRetryBacklog = liveAgents.filter((a) => (a.submit_queue_pending ?? 0) > 0);
  const totalRetryQueuePending = agentsWithRetryBacklog.reduce((sum, a) => sum + (a.submit_queue_pending ?? 0), 0);
  // 20 is a display-only heuristic, not a hard system limit (unlike
  // internal/submitqueue's own maxAttempts=10 per-entry retry cap) - a
  // handful of entries is normal during a brief webserver blip and
  // resolves itself within a retry interval or two; a much larger
  // fleet-wide total suggests something is actually stuck (e.g. a
  // scanner that can't reach the webserver at all anymore).
  const retryQueueStatus: HealthStatus =
    totalRetryQueuePending === 0 ? "ok" : totalRetryQueuePending >= 20 ? "critical" : "warning";

  const overall = worstOf(scannerStatus, updatesStatus, queueStatus, retryQueueStatus, webserverCert ? webserverCertStatus : "ok");

  return {
    loading,
    error,
    overall,
    scannerStatus,
    updatesStatus,
    queueStatus,
    retryQueueStatus,
    webserverCertStatus,
    liveAgents,
    staleJobs,
    activeScanJobs,
    behindAgents,
    pendingUpdates,
    failedUpdates,
    latestRelease,
    scanQueue,
    oldestQueuedMs,
    agentsWithRetryBacklog,
    totalRetryQueuePending,
    webserverCert,
  };
}
