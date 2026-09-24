import { useState } from "react";
import { Link } from "react-router";
import { api, Me, ScannerOverlap } from "../api";
import { IconCheck, IconWarning } from "../components/icons";
import PageHeader from "../components/PageHeader";
import { certExpiryDaysLeft, certExpiryLabel } from "../lib/certExpiry";
import { elapsedLabel } from "../lib/elapsed";
import { formatDateOnly } from "../lib/formatDate";
import {
  HealthStatus,
  NUCLEI_TEMPLATES_WARN_DAYS,
  STALE_QUEUE_THRESHOLD_MS,
  STATUS_LABEL,
  useFleetHealth,
} from "../lib/useFleetHealth";

// `to` is optional: a card that carries its own control cannot also be
// one big anchor, since a button inside a link is neither reliably
// clickable nor valid markup.
function HealthCard({
  to,
  title,
  status,
  children,
}: {
  to?: string;
  title: string;
  status: HealthStatus;
  children: React.ReactNode;
}) {
  const body = (
    <>
      <div className="health-card-title">{title}</div>
      <div className={`health-card-status health-${status}`}>{STATUS_LABEL[status]}</div>
      <div className="health-card-detail">{children}</div>
    </>
  );
  return to ? (
    <Link to={to} className={`health-card health-${status}`}>
      {body}
    </Link>
  ) : (
    <div className={`health-card health-${status}`}>{body}</div>
  );
}

const ACCEPT_DAYS = [30, 90, 180];

// The card that has to say *why* an address is duplicated, because the
// two causes call for opposite responses - see the server's
// search/duplicateCoverage.ts.
function DuplicateCoverageCard({
  me,
  overlap,
  status,
  onChanged,
}: {
  me: Me;
  overlap: ScannerOverlap;
  status: HealthStatus;
  onChanged: (o: ScannerOverlap) => void;
}) {
  const isAdmin = me.role === "admin";
  const [days, setDays] = useState(ACCEPT_DAYS[0]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ack = overlap.acknowledgement;
  const duplicated = overlap.duplicatedAddresses;
  const allStale = duplicated > 0 && overlap.staleDuplicates === duplicated;
  const someStale = overlap.staleDuplicates > 0;
  const example = overlap.duplicates[0];

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      const until = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      onChanged(await api.acknowledgeOverlap(until));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record that.");
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    setError(null);
    try {
      onChanged(await api.clearOverlapAcknowledgement());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not clear that.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <HealthCard title="Duplicate Coverage" status={status}>
      {overlap.hostRows} host record{overlap.hostRows === 1 ? "" : "s"} for {overlap.distinctAddresses} address
      {overlap.distinctAddresses === 1 ? "" : "es"}
      <br />
      {duplicated === 0 ? (
        "No address is covered by more than one scanner"
      ) : (
        <>
          {duplicated} address{duplicated === 1 ? " is" : "es are"} held by more than one scanner, so those machines
          are counted twice in every fleet-wide figure
          {example && (
            <>
              {" "}
              (e.g. {example.ip} via {example.holders.map((h) => h.scanner).join(" and ")})
            </>
          )}
          .{" "}
          {/* The advice, and the reason this card knows which to give:
              rows nobody is refreshing are not double coverage at all. */}
          {allStale ? (
            <>
              Nothing is scanning these twice any more - on every one of them, one scanner's rows have not been
              refreshed in a fortnight or longer. Delete the stale side (filter the host list by that scanner and the
              range, then Delete selected), or leave them to age out through retention.
            </>
          ) : someStale ? (
            <>
              On {overlap.staleDuplicates} of them one scanner's rows are already stale and only need clearing out;
              the rest are genuinely being scanned twice, so narrow one scanner's target range or keep the redundancy
              deliberately.
            </>
          ) : (
            <>Both scanners are still scanning these. Narrow one scanner's target range, or keep it deliberately.</>
          )}
        </>
      )}
      {ack && (
        <>
          <br />
          {ack.active ? (
            <>
              Accepted until {formatDateOnly(ack.until, me.preferences)}
              {ack.by ? ` by ${ack.by}` : ""}
              {ack.acceptedCount !== null && ` (${ack.acceptedCount} accepted)`}.
            </>
          ) : (
            <>
              An earlier acceptance no longer applies -{" "}
              {new Date(ack.until).getTime() <= Date.now()
                ? `it expired on ${formatDateOnly(ack.until, me.preferences)}`
                : `more addresses are duplicated now than the ${ack.acceptedCount} that were accepted`}
              .
            </>
          )}
        </>
      )}
      {isAdmin && duplicated > 0 && (
        <div className="inline-actions health-card-actions">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} disabled={busy}>
            {ACCEPT_DAYS.map((d) => (
              <option key={d} value={d}>
                {d} days
              </option>
            ))}
          </select>
          <button type="button" onClick={accept} disabled={busy}>
            {ack?.active ? "Extend" : "Accept"}
          </button>
          {ack && (
            <button type="button" className="link-button" onClick={clear} disabled={busy}>
              Remove acceptance
            </button>
          )}
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </HealthCard>
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
        A single overview of scanner staleness, version drift, the scan queue backlog, duplicate scanner coverage, and
        the webserver's own TLS certificate expiry - each card links to the page with the full detail.
      </p>

      {health.overall === "ok" ? (
        <div className="callout-success">
          <IconCheck /> All systems normal - no stale scans, no scan queue backlog, no submission retry backlog, and
          no certificate expiring soon.
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
          <br />
          <span className="host-meta">
            Warns at {health.queueWarningThreshold}+ pending
            {me.role === "admin" && " (change this on the Settings page)"}
          </span>
        </HealthCard>

        <HealthCard to="/agents" title="Nuclei Templates" status={health.nucleiTemplatesStatus}>
          {health.oldestTemplateAgeDays === null
            ? "No scanner reports template age"
            : `Oldest: ${health.oldestTemplateAgeDays}d old`}
          <br />
          {health.oldestTemplateAgeDays === null
            ? "nuclei may not be installed, or the scanners predate this reporting"
            : health.staleTemplateAgents.length > 0
              ? `${health.staleTemplateAgents.length} scanner${health.staleTemplateAgents.length === 1 ? "" : "s"} over ${NUCLEI_TEMPLATES_WARN_DAYS}d - refresh from Scanner Agents`
              : "All scanners reasonably current"}
        </HealthCard>

        {health.overlap && (
          <DuplicateCoverageCard
            me={me}
            overlap={health.overlap}
            status={health.overlapStatus}
            onChanged={health.setOverlap}
          />
        )}

        <HealthCard to="/agents" title="Submission Retry Backlog" status={health.retryQueueStatus}>
          {health.totalRetryQueuePending} host submission{health.totalRetryQueuePending === 1 ? "" : "s"} waiting to
          be retried
          <br />
          {health.agentsWithRetryBacklog.length > 0
            ? `${health.agentsWithRetryBacklog.length} scanner${health.agentsWithRetryBacklog.length === 1 ? "" : "s"} affected`
            : "Nothing queued for retry"}
        </HealthCard>

        {me.role === "admin" && health.webserverRelease && (
          <HealthCard to="/settings" title="Webserver Version" status={health.webserverVersionStatus}>
            {health.webserverRelease.lastError ? (
              <>
                Running {health.webserverRelease.runningVersion}. Could not reach Docker Hub to check for a newer
                image: {health.webserverRelease.lastError}
                {health.webserverRelease.latestVersion &&
                  ` Last known published version was ${health.webserverRelease.latestVersion}.`}
              </>
            ) : health.webserverRelease.updateAvailable === null ? (
              <>Running {health.webserverRelease.runningVersion}. Not checked against Docker Hub yet.</>
            ) : health.webserverRelease.updateAvailable ? (
              <>
                Running {health.webserverRelease.runningVersion} — {health.webserverRelease.latestVersion} is published.
                Update with <code>docker compose pull webserver &amp;&amp; docker compose up -d webserver</code> on the
                host; the webserver cannot replace its own container.
              </>
            ) : (
              <>Running {health.webserverRelease.runningVersion}, the newest published version.</>
            )}
          </HealthCard>
        )}

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
