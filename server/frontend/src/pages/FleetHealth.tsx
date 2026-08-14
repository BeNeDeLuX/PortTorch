import { useEffect, useState } from "react";
import { Link } from "react-router";
import {
  ActiveScanJob,
  api,
  ExpiringCertificate,
  Me,
  QueuedScanRequest,
  ScannerAgent,
  ScannerReleaseInfo,
  TlsCertificateInfo,
} from "../api";
import { IconCheck, IconWarning } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { certExpiryDaysLeft, certExpiryLabel, certExpiryStatus } from "../lib/certExpiry";
import { elapsedLabel } from "../lib/elapsed";

type HealthStatus = "ok" | "warning" | "critical";

const STATUS_RANK: Record<HealthStatus, number> = { ok: 0, warning: 1, critical: 2 };
const STATUS_LABEL: Record<HealthStatus, string> = { ok: "OK", warning: "Warning", critical: "Critical" };

function worstOf(...statuses: HealthStatus[]): HealthStatus {
  return statuses.reduce((worst, s) => (STATUS_RANK[s] > STATUS_RANK[worst] ? s : worst), "ok" as HealthStatus);
}

// Same plain X.Y.Z compare as ScannerAgents.tsx's own copy (and the
// webserver's/scanner's own compareSemver) - kept as an independent copy
// rather than a shared import since it's a tiny, self-contained function
// and this page has no other reason to depend on ScannerAgents.tsx.
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
// its own view" section, which documents a real case of 20+ hourly
// requests stacking up for an agent that had gone quiet. This is a
// display-only heuristic (no server-side equivalent), same spirit as
// ScannerAgents.tsx's own RECENTLY_SEEN_THRESHOLD_MS.
const STALE_QUEUE_THRESHOLD_MS = 30 * 60_000;

function HealthCard({
  to,
  title,
  status,
  children,
}: {
  to: string;
  title: string;
  status: HealthStatus;
  children: React.ReactNode;
}) {
  return (
    <Link to={to} className={`health-card health-${status}`}>
      <div className="health-card-title">{title}</div>
      <div className={`health-card-status health-${status}`}>{STATUS_LABEL[status]}</div>
      <div className="health-card-detail">{children}</div>
    </Link>
  );
}

// A read-only dashboard aggregating signals that otherwise only show up
// scattered across the Scanner Agents, Certificates, and Settings pages -
// scanner staleness/version drift, the scan_requests queue backlog,
// pending self-update outcomes, and TLS certificate expiry (both fleet-
// wide and the webserver's own). No new backend endpoints - every card
// is computed client-side from data these other pages already fetch.
export default function FleetHealth({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [loading, setLoading] = useState(true);
  const [agents, setAgents] = useState<ScannerAgent[]>([]);
  const [latestRelease, setLatestRelease] = useState<ScannerReleaseInfo | null>(null);
  const [activeScanJobs, setActiveScanJobs] = useState<ActiveScanJob[]>([]);
  const [scanQueue, setScanQueue] = useState<QueuedScanRequest[]>([]);
  const [certs, setCerts] = useState<ExpiringCertificate[]>([]);
  const [webserverCert, setWebserverCert] = useState<TlsCertificateInfo | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(false);
    Promise.all([
      api.agents(),
      api.latestScannerRelease().catch(() => null),
      api.expiringCertificates(),
      me.role === "admin" ? api.tlsCertificate().catch(() => null) : Promise.resolve(null),
    ])
      .then(([a, release, c, ws]) => {
        setAgents(a);
        setLatestRelease(release);
        setCerts(c);
        setWebserverCert(ws);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
    loadActiveScanJobs();
    loadScanQueue();
    // Same 5s cadence as ScannerAgents.tsx / Dashboard's own active-scans
    // polling - this page surfaces the same underlying data, so it should
    // feel just as live.
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

  if (loading) {
    return (
      <div className="dashboard">
        <PageHeader me={me} onLogout={onLogout} />
        <h2>Fleet Health</h2>
        <p>Loading...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <PageHeader me={me} onLogout={onLogout} />
        <h2>Fleet Health</h2>
        <p className="error">Could not load fleet health data.</p>
      </div>
    );
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
    scanQueue.length > 0
      ? Math.max(...scanQueue.map((q) => Date.now() - new Date(q.created_at).getTime()))
      : 0;
  const queueStatus: HealthStatus =
    scanQueue.length === 0 ? "ok" : oldestQueuedMs > STALE_QUEUE_THRESHOLD_MS ? "critical" : "warning";

  const soonCerts = certs.filter((c) => certExpiryStatus(c.not_after) === "soon");
  const expiredCerts = certs.filter((c) => certExpiryStatus(c.not_after) === "expired");
  const certStatus: HealthStatus = expiredCerts.length > 0 ? "critical" : soonCerts.length > 0 ? "warning" : "ok";

  const webserverCertRawStatus = webserverCert ? certExpiryStatus(webserverCert.validTo) : "ok";
  const webserverCertStatus: HealthStatus =
    webserverCertRawStatus === "expired" ? "critical" : webserverCertRawStatus === "soon" ? "warning" : "ok";

  const overall = worstOf(
    scannerStatus,
    updatesStatus,
    queueStatus,
    certStatus,
    webserverCert ? webserverCertStatus : "ok"
  );

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Fleet Health</h2>
      <p className="host-meta">
        A single overview of scanner staleness, version drift, the scan queue backlog, and TLS certificate expiry -
        each card links to the page with the full detail.
      </p>

      {overall === "ok" ? (
        <div className="callout">
          <IconCheck /> All systems normal - no stale scans, no queue backlog, and no certificates expiring soon.
        </div>
      ) : overall === "warning" ? (
        <div className="callout-warning">
          <IconWarning /> One or more areas need attention soon - see the highlighted cards below.
        </div>
      ) : (
        <div className="callout-danger">
          <IconWarning /> One or more areas need attention now - see the highlighted cards below.
        </div>
      )}

      <div className="health-grid">
        <HealthCard to="/agents" title="Scanner Fleet" status={scannerStatus}>
          {liveAgents.length} active scanner{liveAgents.length === 1 ? "" : "s"}, {activeScanJobs.length} running now
          <br />
          {staleJobs.length > 0
            ? `${staleJobs.length} stale scan${staleJobs.length === 1 ? "" : "s"} - may have died mid-scan`
            : "No stale scans"}
        </HealthCard>

        <HealthCard to="/agents" title="Scanner Updates" status={updatesStatus}>
          {latestRelease?.latestVersion ? `Latest release: v${latestRelease.latestVersion}` : "Latest release unknown"}
          <br />
          {behindAgents.length > 0 ? `${behindAgents.length} behind` : "All up to date"}
          {pendingUpdates.length > 0 && `, ${pendingUpdates.length} update pending`}
          {failedUpdates.length > 0 && `, ${failedUpdates.length} update failed`}
        </HealthCard>

        <HealthCard to="/agents" title="Scan Queue" status={queueStatus}>
          {scanQueue.length} pending request{scanQueue.length === 1 ? "" : "s"}
          <br />
          {scanQueue.length > 0
            ? `Oldest queued ${elapsedLabel(
                new Date(Date.now() - oldestQueuedMs).toISOString()
              )} ago${oldestQueuedMs > STALE_QUEUE_THRESHOLD_MS ? " - target scanner may have stopped polling" : ""}`
            : "Nothing waiting"}
        </HealthCard>

        <HealthCard to="/certificates" title="Fleet TLS Certificates" status={certStatus}>
          {certs.length} certificate{certs.length === 1 ? "" : "s"} across all hosts
          <br />
          {expiredCerts.length > 0 && `${expiredCerts.length} expired`}
          {expiredCerts.length > 0 && soonCerts.length > 0 && ", "}
          {soonCerts.length > 0 && `${soonCerts.length} expiring soon`}
          {expiredCerts.length === 0 && soonCerts.length === 0 && "None expiring soon"}
        </HealthCard>

        {me.role === "admin" && webserverCert && (
          <HealthCard to="/settings" title="Webserver TLS Certificate" status={webserverCertStatus}>
            {certExpiryLabel(webserverCert.validTo)}
            {(() => {
              const days = certExpiryDaysLeft(webserverCert.validTo);
              if (days === null) return null;
              return days >= 0 ? ` (${days}d left)` : ` (${-days}d ago)`;
            })()}
          </HealthCard>
        )}
      </div>
    </div>
  );
}
