import { useEffect, useState } from "react";
import {
  ActiveScanJob,
  api,
  Me,
  QueuedScanRequest,
  ScannerAgent,
  ScannerReleaseInfo,
  TlsCertificateInfo,
  WebserverReleaseStatus,
} from "../api";
import { certExpiryStatus } from "./certExpiry";
import { isVersionBehind } from "./semver";

export type HealthStatus = "ok" | "warning" | "critical";

export const STATUS_RANK: Record<HealthStatus, number> = { ok: 0, warning: 1, critical: 2 };
export const STATUS_LABEL: Record<HealthStatus, string> = { ok: "OK", warning: "Warning", critical: "Critical" };

export function worstOf(...statuses: HealthStatus[]): HealthStatus {
  return statuses.reduce((worst, s) => (STATUS_RANK[s] > STATUS_RANK[worst] ? s : worst), "ok" as HealthStatus);
}


// A queued scan_requests row older than this strongly suggests the
// target scanner has stopped polling entirely, rather than just being
// mid-scan on something else - see CLAUDE.md's "Scan request queue as
// its own view" section. Display-only heuristic, same spirit as
// ScannerAgents.tsx's own RECENTLY_SEEN_THRESHOLD_MS.
export const STALE_QUEUE_THRESHOLD_MS = 30 * 60_000;

// nuclei templates are fetched once at install and never refreshed
// automatically, so they age silently - a scan with stale templates looks
// identical to one with current templates, it just finds less. These
// thresholds are display-only heuristics: template releases land more or
// less continuously, so a month is comfortably "getting old" and a
// quarter is "you are almost certainly missing recent checks".
export const NUCLEI_TEMPLATES_WARN_DAYS = 30;
export const NUCLEI_TEMPLATES_CRITICAL_DAYS = 90;

export interface FleetHealthData {
  loading: boolean;
  error: boolean;
  overall: HealthStatus;
  scannerStatus: HealthStatus;
  updatesStatus: HealthStatus;
  queueStatus: HealthStatus;
  retryQueueStatus: HealthStatus;
  webserverCertStatus: HealthStatus;
  webserverVersionStatus: HealthStatus;
  nucleiTemplatesStatus: HealthStatus;
  liveAgents: ScannerAgent[];
  staleJobs: ActiveScanJob[];
  activeScanJobs: ActiveScanJob[];
  behindAgents: ScannerAgent[];
  pendingUpdates: ScannerAgent[];
  failedUpdates: ScannerAgent[];
  latestRelease: ScannerReleaseInfo | null;
  scanQueue: QueuedScanRequest[];
  oldestQueuedMs: number;
  queueWarningThreshold: number;
  agentsWithRetryBacklog: ScannerAgent[];
  totalRetryQueuePending: number;
  webserverCert: TlsCertificateInfo | null;
  webserverRelease: WebserverReleaseStatus | null;
  // Agents whose templates are old enough to warrant attention, and the
  // single oldest age in days (null when no agent reports one at all).
  staleTemplateAgents: ScannerAgent[];
  oldestTemplateAgeDays: number | null;
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
  const [webserverRelease, setWebserverRelease] = useState<WebserverReleaseStatus | null>(null);
  // How many pending requests before the queue counts as a "warning" -
  // admin-editable (Settings page), defaults to 1 (today's behavior)
  // until that first fetch resolves.
  const [queueWarningThreshold, setQueueWarningThreshold] = useState(1);

  useEffect(() => {
    setLoading(true);
    setError(false);
    Promise.all([
      api.agents(),
      api.latestScannerRelease().catch(() => null),
      me.role === "admin" ? api.tlsCertificate().catch(() => null) : Promise.resolve(null),
      api.scanQueueThreshold().catch(() => null),
      // Admin-only like the certificate above: both live behind the
      // settings router, and both are about the webserver itself rather
      // than the fleet it watches.
      me.role === "admin" ? api.webserverRelease().catch(() => null) : Promise.resolve(null),
    ])
      .then(([a, release, ws, threshold, serverRelease]) => {
        setAgents(a);
        setLatestRelease(release);
        setWebserverCert(ws);
        setWebserverRelease(serverRelease);
        if (threshold) setQueueWarningThreshold(threshold.warningThreshold);
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
  // A newer release existing (or an update an admin already requested
  // still being applied) isn't itself a problem worth a "Warning" badge -
  // only an update that actually *failed* is something that needs
  // attention. Version drift/pending-ness still shows as a plain, muted
  // detail line on the card itself (see FleetHealth.tsx) - a quiet fact,
  // not an escalated status.
  const updatesStatus: HealthStatus = failedUpdates.length > 0 ? "critical" : "ok";

  const oldestQueuedMs =
    scanQueue.length > 0 ? Math.max(...scanQueue.map((q) => Date.now() - new Date(q.created_at).getTime())) : 0;
  // A single request stuck for 30+ min still escalates straight to
  // critical regardless of queueWarningThreshold - that specifically
  // means a scanner has stopped polling, not just "the queue is a bit
  // busy," and staying below the count threshold shouldn't mask it. The
  // count threshold only gates the milder "warning" tier, since a queue
  // depth an admin has explicitly said is normal shouldn't page anyone.
  const queueStatus: HealthStatus =
    scanQueue.length === 0
      ? "ok"
      : oldestQueuedMs > STALE_QUEUE_THRESHOLD_MS
        ? "critical"
        : scanQueue.length >= queueWarningThreshold
          ? "warning"
          : "ok";

  const webserverCertRawStatus = webserverCert ? certExpiryStatus(webserverCert.validTo) : "ok";
  const webserverCertStatus: HealthStatus =
    webserverCertRawStatus === "expired" ? "critical" : webserverCertRawStatus === "soon" ? "warning" : "ok";

  // A newer published image is a "warning", never critical: the running
  // webserver is working, and an update is a thing to plan rather than an
  // outage. Deliberately the same call the Scanner Updates card makes for
  // a behind-version scanner - see its own note on why a newer release
  // existing is not itself a problem.
  //
  // A failed or never-run check is *also* a warning rather than "ok":
  // "we could not find out" and "you are current" are different answers,
  // and silently showing the second for the first is how an instance sits
  // a year behind without anyone noticing.
  const webserverVersionStatus: HealthStatus = !webserverRelease
    ? "ok"
    : webserverRelease.updateAvailable === null || webserverRelease.lastError
      ? "warning"
      : webserverRelease.updateAvailable
        ? "warning"
        : "ok";

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

  // Only agents that actually report a template date are considered -
  // "unknown" (nuclei not installed, or an older scanner build) is not
  // evidence of staleness and must not raise an alarm on a fleet that
  // deliberately doesn't run nuclei at all.
  const templateAges = liveAgents
    .filter((a) => a.nuclei_templates_updated_at)
    .map((a) => ({ agent: a, days: (Date.now() - new Date(a.nuclei_templates_updated_at!).getTime()) / 86_400_000 }));
  const oldestTemplateAgeDays = templateAges.length > 0 ? Math.floor(Math.max(...templateAges.map((t) => t.days))) : null;
  const staleTemplateAgents = templateAges.filter((t) => t.days >= NUCLEI_TEMPLATES_WARN_DAYS).map((t) => t.agent);
  const nucleiTemplatesStatus: HealthStatus =
    oldestTemplateAgeDays === null
      ? "ok"
      : oldestTemplateAgeDays >= NUCLEI_TEMPLATES_CRITICAL_DAYS
        ? "critical"
        : oldestTemplateAgeDays >= NUCLEI_TEMPLATES_WARN_DAYS
          ? "warning"
          : "ok";

  const overall = worstOf(
    scannerStatus,
    updatesStatus,
    queueStatus,
    retryQueueStatus,
    nucleiTemplatesStatus,
    webserverCert ? webserverCertStatus : "ok",
    webserverVersionStatus
  );

  return {
    loading,
    error,
    overall,
    scannerStatus,
    updatesStatus,
    queueStatus,
    retryQueueStatus,
    webserverCertStatus,
    webserverVersionStatus,
    nucleiTemplatesStatus,
    liveAgents,
    staleJobs,
    activeScanJobs,
    behindAgents,
    pendingUpdates,
    failedUpdates,
    latestRelease,
    scanQueue,
    oldestQueuedMs,
    queueWarningThreshold,
    agentsWithRetryBacklog,
    totalRetryQueuePending,
    webserverCert,
    webserverRelease,
    staleTemplateAgents,
    oldestTemplateAgeDays,
  };
}
