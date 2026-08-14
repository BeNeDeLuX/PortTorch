import { Link } from "react-router";
import { Me } from "../api";
import { IconCheck, IconWarning } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { certExpiryDaysLeft, certExpiryLabel } from "../lib/certExpiry";
import { elapsedLabel } from "../lib/elapsed";
import { HealthStatus, STALE_QUEUE_THRESHOLD_MS, STATUS_LABEL, useFleetHealth } from "../lib/useFleetHealth";

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
// scattered across the Scanner Agents and Settings pages - scanner
// staleness/version drift, the scan_requests queue backlog, pending
// self-update outcomes, and the webserver's own TLS certificate expiry.
// Deliberately doesn't include the fleet-wide Certificates page (TLS
// certs captured *from scanned hosts*) - those devices aren't part of
// "our fleet" the way the scanners/webserver itself are, so their
// certificate hygiene isn't this page's concern. No new backend
// endpoints - every card is computed client-side (see lib/useFleetHealth,
// shared with the Dashboard's own small "needs attention" banner) from
// data these other pages already fetch.
export default function FleetHealth({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const health = useFleetHealth(me);

  if (health.loading) {
    return (
      <div className="dashboard">
        <PageHeader me={me} onLogout={onLogout} />
        <h2>Fleet Health</h2>
        <p>Loading...</p>
      </div>
    );
  }

  if (health.error) {
    return (
      <div className="dashboard">
        <PageHeader me={me} onLogout={onLogout} />
        <h2>Fleet Health</h2>
        <p className="error">Could not load fleet health data.</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <PageHeader me={me} onLogout={onLogout} />

      <h2>Fleet Health</h2>
      <p className="host-meta">
        A single overview of scanner staleness, version drift, the scan queue backlog, and the webserver's own TLS
        certificate expiry - each card links to the page with the full detail.
      </p>

      {health.overall === "ok" ? (
        <div className="callout">
          <IconCheck /> All systems normal - no stale scans, no queue backlog, and no certificate expiring soon.
        </div>
      ) : health.overall === "warning" ? (
        <div className="callout-warning">
          <IconWarning /> One or more areas need attention soon - see the highlighted cards below.
        </div>
      ) : (
        <div className="callout-danger">
          <IconWarning /> One or more areas need attention now - see the highlighted cards below.
        </div>
      )}

      <div className="health-grid">
        <HealthCard to="/agents" title="Scanner Fleet" status={health.scannerStatus}>
          {health.liveAgents.length} active scanner{health.liveAgents.length === 1 ? "" : "s"},{" "}
          {health.activeScanJobs.length} running now
          <br />
          {health.staleJobs.length > 0
            ? `${health.staleJobs.length} stale scan${health.staleJobs.length === 1 ? "" : "s"} - may have died mid-scan`
            : "No stale scans"}
        </HealthCard>

        <HealthCard to="/agents" title="Scanner Updates" status={health.updatesStatus}>
          {health.latestRelease?.latestVersion
            ? `Latest release: v${health.latestRelease.latestVersion}`
            : "Latest release unknown"}
          <br />
          {health.behindAgents.length > 0 ? `${health.behindAgents.length} behind` : "All up to date"}
          {health.pendingUpdates.length > 0 && `, ${health.pendingUpdates.length} update pending`}
          {health.failedUpdates.length > 0 && `, ${health.failedUpdates.length} update failed`}
        </HealthCard>

        <HealthCard to="/agents" title="Scan Queue" status={health.queueStatus}>
          {health.scanQueue.length} pending request{health.scanQueue.length === 1 ? "" : "s"}
          <br />
          {health.scanQueue.length > 0
            ? `Oldest queued ${elapsedLabel(
                new Date(Date.now() - health.oldestQueuedMs).toISOString()
              )} ago${health.oldestQueuedMs > STALE_QUEUE_THRESHOLD_MS ? " - target scanner may have stopped polling" : ""}`
            : "Nothing waiting"}
        </HealthCard>

        {me.role === "admin" && health.webserverCert && (
          <HealthCard to="/settings" title="Webserver TLS Certificate" status={health.webserverCertStatus}>
            {certExpiryLabel(health.webserverCert.validTo)}
            {(() => {
              const days = certExpiryDaysLeft(health.webserverCert.validTo);
              if (days === null) return null;
              return days >= 0 ? ` (${days}d left)` : ` (${-days}d ago)`;
            })()}
          </HealthCard>
        )}
      </div>
    </div>
  );
}
