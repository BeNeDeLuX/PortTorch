import { FormEvent, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import { api, HostDetail as HostDetailData, HostFilters, Me } from "../api";
import { certExpiryStatus, certExpiryLabel } from "../lib/certExpiry";
import { cveSeverityClass } from "../lib/cveSeverity";
import PageHeader from "../components/PageHeader";
import { formatDateTime, formatDateOnly } from "../lib/formatDate";
import Lightbox, { LightboxItem } from "../components/Lightbox";
import HostExportModal from "../components/HostExportModal";

// Router state Dashboard.tsx hands off when navigating to a host - see
// the prev/next wiring further down for how each field is used.
interface HostNavState {
  hostIds?: string[];
  filters?: HostFilters;
  page?: number;
  pageSize?: number;
  total?: number;
}

const RESCAN_STATUS_LABEL: Record<string, string> = {
  pending: "requested, waiting for the scanner to pick it up",
  claimed: "currently running on the scanner",
  completed: "completed",
  failed: "failed",
  cancelled: "stopped by an operator",
};

// Human-readable label per NSE script id captured in a port's nse_extra
// array (see db/types.ts's NSEScriptEntry / scanner's PortResult.ExtraScripts)
// - falls back to the raw script id for anything not listed here, so a
// script added later on the scanner side still displays (just less
// prettily) without needing a matching frontend change.
const NSE_SCRIPT_LABELS: Record<string, string> = {
  "nfs-showmount": "NFS exports",
  "rsync-list-modules": "rsync modules",
  "ldap-rootdse": "LDAP root DSE",
  "mongodb-info": "MongoDB info",
  "mongodb-databases": "MongoDB databases",
  "redis-info": "Redis info",
  "docker-version": "Docker API info",
  "couchdb-databases": "CouchDB databases",
  "cassandra-info": "Cassandra info",
  "smtp-open-relay": "SMTP open relay test",
  "snmp-info": "SNMP info",
  "smb-os-discovery": "SMB OS discovery",
  "nbstat": "NetBIOS name/domain",
  "http-methods": "HTTP methods",
  "smb-protocols": "SMB protocol versions",
  "smb-security-mode": "SMB security mode",
  "smb2-security-mode": "SMB2 security mode",
  "mysql-info": "MySQL info",
  "http-auth": "HTTP auth scheme",
  "http-git": "Exposed .git repository",
  "rdp-ntlm-info": "RDP NTLM info",
  "rdp-enum-encryption": "RDP encryption level",
  "ssh2-enum-algos": "SSH2 algorithms",
  "sshv1": "SSHv1 supported",
  "ipmi-version": "IPMI/BMC info",
  "rpcinfo": "RPC portmapper programs",
  "msrpc-enum": "MSRPC endpoint mapper",
  "memcached-info": "Memcached info",
  "oracle-tns-version": "Oracle TNS version",
  "snmp-sysdescr": "SNMP system description",
  "snmp-interfaces": "SNMP network interfaces",
  "snmp-netstat": "SNMP connection table",
  "dns-recursion": "Open recursive DNS resolver",
};

export default function HostDetail({ me, onLogout }: { me: Me; onLogout: () => void }) {
  // Admin and operator share the same host-editing rights here (rescan,
  // tags, comments) - only scanner agents/schedules/webhooks/users are
  // admin-only.
  const canEdit = me.role === "admin" || me.role === "operator";
  const isAdmin = me.role === "admin";
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const [pageNavBusy, setPageNavBusy] = useState(false);
  // Set by Dashboard.tsx when navigating here from the host list - the ids
  // of whatever page of (filtered/sorted) results was on screen at the
  // time, plus enough of the dashboard's own query (filters/page/pageSize/
  // total) to fetch the *next* or *previous page* once we run off either
  // end of this one. Forwarded along on every prev/next click so browsing
  // keeps working across several hosts (and pages) in a row. Absent
  // entirely if this page was opened directly (bookmark, refresh), in
  // which case prev/next simply don't render.
  const navState = (location.state as HostNavState | null) ?? {};
  const hostIds = navState.hostIds;
  const currentIndex = id && hostIds ? hostIds.indexOf(id) : -1;
  const prevHostId = currentIndex > 0 ? hostIds![currentIndex - 1] : undefined;
  const nextHostId =
    currentIndex >= 0 && hostIds && currentIndex < hostIds.length - 1 ? hostIds[currentIndex + 1] : undefined;
  const isFirstOfPage = currentIndex === 0;
  const isLastOfPage = !!hostIds && currentIndex === hostIds.length - 1;
  const hasPrevPage = !!navState.page && navState.page > 1;
  const hasNextPage =
    !!navState.page && !!navState.pageSize && navState.total !== undefined && navState.page * navState.pageSize < navState.total;
  const showPrev = prevHostId !== undefined || (isFirstOfPage && hasPrevPage);
  const showNext = nextHostId !== undefined || (isLastOfPage && hasNextPage);

  function goToHost(hostId: string, state: HostNavState) {
    navigate(`/hosts/${hostId}`, { state });
  }

  async function handlePrev() {
    if (prevHostId) {
      goToHost(prevHostId, navState);
      return;
    }
    if (isFirstOfPage && hasPrevPage && navState.filters && navState.page && navState.pageSize) {
      setPageNavBusy(true);
      try {
        // Crossing into the previous page always lands on its *last* host
        // in server order - a client-only table sort (Dashboard.tsx's
        // column-header sort) doesn't extend across separately-fetched
        // pages, so there's no other well-defined "last" item to land on.
        const prevPage = await api.hosts(navState.filters, navState.page - 1, navState.pageSize);
        const ids = prevPage.items.map((h) => h.id);
        const lastId = ids[ids.length - 1];
        if (lastId) {
          goToHost(lastId, { ...navState, hostIds: ids, page: navState.page - 1 });
        }
      } finally {
        setPageNavBusy(false);
      }
      return;
    }
    navigate(-1);
  }

  async function handleNext() {
    if (nextHostId) {
      goToHost(nextHostId, navState);
      return;
    }
    if (isLastOfPage && hasNextPage && navState.filters && navState.page && navState.pageSize) {
      setPageNavBusy(true);
      try {
        const nextPage = await api.hosts(navState.filters, navState.page + 1, navState.pageSize);
        const ids = nextPage.items.map((h) => h.id);
        const firstId = ids[0];
        if (firstId) {
          goToHost(firstId, { ...navState, hostIds: ids, page: navState.page + 1 });
        }
      } finally {
        setPageNavBusy(false);
      }
    }
  }
  const [data, setData] = useState<HostDetailData | null>(null);
  const [rescanError, setRescanError] = useState<string | null>(null);
  const [showExportModal, setShowExportModal] = useState(false);
  const [newTag, setNewTag] = useState("");
  const [newComment, setNewComment] = useState("");
  const [probeHostnameInput, setProbeHostnameInput] = useState("");
  const [lightbox, setLightbox] = useState<{ items: LightboxItem[]; index: number } | null>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    if (id) {
      load(id);
    }
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [id]);

  async function load(hostId: string) {
    const fresh = await api.host(hostId);
    setData(fresh);
    // Only seeded here (on an explicit reload after a user action), not
    // from a passive background refresh (startPollingForRescan below sets
    // data directly, bypassing this) - otherwise the 5s rescan poll would
    // stomp on whatever the user is currently typing into this field.
    setProbeHostnameInput(fresh.host.probe_hostname ?? "");
  }

  function startPollingForRescan(hostId: string) {
    if (pollRef.current) window.clearInterval(pollRef.current);
    let attempts = 0;
    pollRef.current = window.setInterval(async () => {
      attempts += 1;
      const fresh = await api.host(hostId);
      setData(fresh);
      const status = fresh.lastScanRequest?.status;
      if (status === "completed" || status === "failed" || attempts >= 20) {
        if (pollRef.current) window.clearInterval(pollRef.current);
      }
    }, 5000);
  }

  async function handleRescan() {
    if (!id) return;
    setRescanError(null);
    try {
      await api.rescan(id);
      await load(id);
      startPollingForRescan(id);
    } catch (err) {
      setRescanError(err instanceof Error ? err.message : "Rescan failed");
    }
  }

  async function handleDismissRescan() {
    if (!id) return;
    if (!window.confirm("Dismiss this stale rescan? The scanner isn't notified - if it's actually still running, its next update is simply ignored.")) {
      return;
    }
    await api.dismissRescan(id);
    await load(id);
  }

  async function handleAddTag(e: FormEvent) {
    e.preventDefault();
    if (!id || !newTag.trim()) return;
    await api.addHostTag(id, newTag.trim());
    setNewTag("");
    await load(id);
  }

  async function handleRemoveTag(tag: string) {
    if (!id) return;
    await api.removeHostTag(id, tag);
    await load(id);
  }

  async function handleSetProbeHostname(e: FormEvent) {
    e.preventDefault();
    if (!id) return;
    // Empty input clears the override back to "use the bare IP" - matches
    // the null-means-no-override convention used elsewhere in this app.
    await api.setHostProbeHostname(id, probeHostnameInput.trim() || null);
    await load(id);
  }

  async function handleAddComment(e: FormEvent) {
    e.preventDefault();
    if (!id || !newComment.trim()) return;
    await api.addHostComment(id, newComment.trim());
    setNewComment("");
    await load(id);
  }

  async function handleDeleteComment(commentId: string) {
    if (!id) return;
    await api.deleteHostComment(id, commentId);
    await load(id);
  }

  if (!data) {
    return <p>Loading...</p>;
  }

  const rescanStatus = data.lastScanRequest?.status;
  const rescanInFlight = rescanStatus === "pending" || rescanStatus === "claimed";
  const historyGroups = groupHistoryByScan(data.history);
  const changes = computeChanges(historyGroups);
  // Comparing each port's own observed_at against this (rather than
  // host.last_seen_at) keeps the comparison within a single clock source -
  // last_seen_at is set from the webserver's own Date.now() while
  // observed_at comes from Postgres's now(), and those two can disagree by
  // a few milliseconds even for ports written in the very same scan,
  // which would otherwise flag every port on a perfectly fresh scan as
  // stale (confirmed this the wrong way round via testing before settling
  // on this fix).
  const latestPortObservedAt = data.ports.reduce(
    (max, p) => Math.max(max, new Date(p.observed_at).getTime()),
    0
  );
  const screenshotItems: LightboxItem[] = data.screenshots.map((s) => ({
    src: `/api/screenshots/${s.id}/image`,
    alt: s.page_title ?? s.url,
  }));
  const rdpScreenshotItems: LightboxItem[] = data.rdpScreenshots.map((s) => ({
    src: `/api/rdp-screenshots/${s.id}/image`,
    alt: `RDP Port ${s.port}`,
  }));

  return (
    <div className="host-detail">
      <PageHeader me={me} onLogout={onLogout} />
      <div className="host-nav-row">
        <button className="back-button" onClick={handlePrev} disabled={pageNavBusy}>
          &larr; {showPrev ? "previous" : "back"}
        </button>
        {showNext && (
          <button className="next-button" onClick={handleNext} disabled={pageNavBusy}>
            {pageNavBusy ? "loading..." : <>next &rarr;</>}
          </button>
        )}
      </div>
      <div className="host-detail-header">
        <h1>
          {data.host.ip} {data.host.hostname && <span className="host-hostname">({data.host.hostname})</span>}
        </h1>
        <button type="button" className="link-button" onClick={() => setShowExportModal(true)}>
          Export data
        </button>
        {canEdit && (
          <button onClick={handleRescan} disabled={rescanInFlight}>
            {rescanInFlight ? "Rescan running..." : "Rescan"}
          </button>
        )}
      </div>
      {showExportModal && <HostExportModal data={data} onClose={() => setShowExportModal(false)} />}
      <p className="host-meta host-seen-summary">
        First seen {formatDateTime(data.host.first_seen_at, me.preferences)} · last seen{" "}
        {formatDateTime(data.host.last_seen_at, me.preferences)}
        {historyGroups[0]?.scannerAgentName && <> · last scanned by {historyGroups[0].scannerAgentName}</>}
      </p>
      <p className="host-meta">
        Probe hostname (used instead of the IP for TLS SNI / screenshot capture, e.g. for a
        target that only routes correctly for a known hostname):{" "}
        {data.host.probe_hostname ?? <em>not set</em>}
      </p>
      {canEdit && (
        <form className="inline-form" onSubmit={handleSetProbeHostname}>
          <input
            placeholder="e.g. example.com - leave blank to clear"
            value={probeHostnameInput}
            onChange={(e) => setProbeHostnameInput(e.target.value)}
          />
          <button type="submit">Save</button>
        </form>
      )}
      {(data.host.os_name || data.host.device_type) && (
        <p className="host-meta">
          {[data.host.device_type, data.host.os_name || data.host.os_family].filter(Boolean).join(" · ")}
          {data.host.os_accuracy ? ` (${data.host.os_accuracy}% confidence)` : ""}
        </p>
      )}
      {data.host.mac_address && (
        <p className="host-meta">
          MAC: <span className="fingerprint">{data.host.mac_address}</span>
          {data.host.mac_vendor && ` (${data.host.mac_vendor})`}
        </p>
      )}

      {(data.tags.length > 0 || canEdit) && (
        <div className="filter-chips">
          {data.tags.map((tag) =>
            canEdit ? (
              <button key={tag} className="chip" onClick={() => handleRemoveTag(tag)}>
                {tag} &times;
              </button>
            ) : (
              <span key={tag} className="chip">
                {tag}
              </span>
            )
          )}
          {canEdit && (
            <form className="inline-form tag-form push-right" onSubmit={handleAddTag}>
              <input placeholder="Add tag..." value={newTag} onChange={(e) => setNewTag(e.target.value)} />
              <button type="submit">Add</button>
            </form>
          )}
        </div>
      )}

      {rescanError && <p className="error">{rescanError}</p>}
      {data.lastScanRequest && (
        <p className="host-meta">
          Last rescan: {RESCAN_STATUS_LABEL[data.lastScanRequest.status] ?? data.lastScanRequest.status} (
          {formatDateTime(data.lastScanRequest.created_at, me.preferences)})
          {data.lastScanRequest.is_stale && (
            <span
              className="stale-badge"
              title="No update in a while - the target scanner may be offline or have died mid-scan"
            >
              stale
            </span>
          )}
          {data.lastScanRequest.is_stale && canEdit && (
            <button className="link-button" onClick={handleDismissRescan}>
              dismiss
            </button>
          )}
        </p>
      )}

      {changes && (
        <section className="callout">
          <h2>Changes since last scan</h2>
          {changes.newlyOpen.length === 0 && changes.newlyClosed.length === 0 && changes.serviceChanged.length === 0 ? (
            <p className="host-meta">No changes since the previous scan.</p>
          ) : (
            <>
              {changes.newlyOpen.length > 0 && (
                <p>
                  <strong>Newly open:</strong>{" "}
                  {changes.newlyOpen.map((p) => p.port + (p.service_name ? `/${p.service_name}` : "")).join(", ")}
                </p>
              )}
              {changes.newlyClosed.length > 0 && (
                <p>
                  <strong>Closed since last scan:</strong>{" "}
                  {changes.newlyClosed.map((p) => p.port + (p.service_name ? `/${p.service_name}` : "")).join(", ")}
                </p>
              )}
              {changes.serviceChanged.length > 0 && (
                <p>
                  <strong>Service changed:</strong>{" "}
                  {changes.serviceChanged.map((c) => `${c.port} (${c.from} → ${c.to})`).join(", ")}
                </p>
              )}
            </>
          )}
        </section>
      )}

      <section>
        <h2>Open Ports</h2>
        <table>
          <thead>
            <tr>
              <th>Port</th>
              <th>Protocol</th>
              <th>Service</th>
              <th>Product/Version</th>
              <th>Banner</th>
              <th>Last confirmed</th>
            </tr>
          </thead>
          <tbody>
            {data.ports.map((p) => {
              // A port only ever gets a fresh observation row when the
              // scanner actually rediscovers it - masscan has no
              // "checked and it's now closed" signal of its own (it's a
              // stateless SYN scanner that just doesn't report a port it
              // gets no response for, indistinguishable at that layer
              // from one lost probe on an otherwise-fine port), so a port
              // that quietly stops answering keeps showing its last-seen
              // "open" row indefinitely instead of ever flipping to
              // closed. Flagging whenever this port's own observation
              // predates this host's most recently observed port is the
              // cheap, false-positive-free signal: it means this specific
              // port wasn't part of the most recent run's results at all.
              const stale = new Date(p.observed_at).getTime() < latestPortObservedAt;
              return (
                <tr key={`${p.port}-${p.protocol}`}>
                  <td>{p.port}</td>
                  <td>{p.protocol}</td>
                  <td>{p.service_name}</td>
                  <td>
                    {p.service_product} {p.service_version}
                    {(p.os_type || p.extra_info) && (
                      <div className="host-meta">{[p.os_type, p.extra_info].filter(Boolean).join(" · ")}</div>
                    )}
                    {p.cpes && p.cpes.length > 0 && <div className="fingerprint">{p.cpes.join(", ")}</div>}
                    {p.vulnerabilities.length > 0 && (
                      <div className="cve-badges">
                        {p.vulnerabilities.map((v) => (
                          <span key={v.id} style={{ display: "inline-flex", gap: "0.25rem", alignItems: "center" }}>
                            <a
                              className={`cve-badge cve-${cveSeverityClass(v)}`}
                              href={`https://nvd.nist.gov/vuln/detail/${v.id}`}
                              target="_blank"
                              rel="noreferrer"
                              title={
                                v.epssScore != null
                                  ? `${v.description}\nEPSS: ${(v.epssScore * 100).toFixed(1)}% likely to be exploited (${Math.round((v.epssPercentile ?? 0) * 100)}th percentile)`
                                  : v.description
                              }
                            >
                              {v.id}
                              {v.cvssScore != null && ` (${v.cvssScore})`}
                              {v.epssScore != null && ` · EPSS ${(v.epssScore * 100).toFixed(1)}%`}
                            </a>
                            {v.kevDateAdded && (
                              <span
                                className="kev-badge"
                                title={`Added to CISA Known Exploited Vulnerabilities catalog ${v.kevDateAdded}${v.kevKnownRansomwareCampaignUse === "Known" ? " - known ransomware campaign use" : ""}`}
                              >
                                KEV
                              </span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="banner">{p.banner}</td>
                  <td>
                    {formatDateTime(p.observed_at, me.preferences)}
                    {stale && (
                      <span
                        className="stale-badge"
                        title="This port wasn't part of the most recent scan's results - it may no longer be open. masscan can't distinguish a genuinely closed port from one lost probe, so this isn't auto-corrected to 'closed'."
                      >
                        stale
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      {(data.ports.some((p) => p.banner || p.ftp_anon_listing || p.smb_shares || (p.nse_extra && p.nse_extra.length > 0)) ||
        data.sshHostKeys.length > 0) && (
        <section>
          <h2>Service Banners &amp; Enumeration</h2>
          <div className="banner-list">
            {data.ports
              .filter(
                (p) =>
                  p.banner ||
                  p.ftp_anon_listing ||
                  p.smb_shares ||
                  (p.nse_extra && p.nse_extra.length > 0) ||
                  data.sshHostKeys.some((k) => k.port === p.port)
              )
              .map((p) => (
                <div key={`${p.port}-${p.protocol}`} className="banner-card">
                  <div className="banner-card-header">
                    Port {p.port} {p.service_name && `· ${p.service_name}`}
                  </div>
                  {p.banner && <pre className="banner-text">{p.banner}</pre>}
                  {p.ftp_anon_listing && (
                    <>
                      <div className="host-meta">
                        <strong>FTP anonymous access</strong>
                      </div>
                      <pre className="banner-text">{p.ftp_anon_listing}</pre>
                    </>
                  )}
                  {p.smb_shares && (
                    <>
                      <div className="host-meta">
                        <strong>SMB shares (anonymous/guest session)</strong>
                      </div>
                      <pre className="banner-text">{p.smb_shares}</pre>
                    </>
                  )}
                  {p.nse_extra?.map((s) => (
                    <div key={s.id}>
                      <div className="host-meta">
                        <strong>{NSE_SCRIPT_LABELS[s.id] ?? s.id}</strong>
                      </div>
                      <pre className="banner-text">{s.output}</pre>
                    </div>
                  ))}
                  {data.sshHostKeys
                    .filter((k) => k.port === p.port)
                    .map((k) => (
                      <div key={k.id} className="ssh-hostkey">
                        <span className="ssh-hostkey-type">
                          {k.key_type}
                          {k.bits ? ` ${k.bits}` : ""}
                        </span>
                        <span className="fingerprint">{k.fingerprint_sha256}</span>
                        {k.fingerprint_md5 && <span className="fingerprint">MD5:{k.fingerprint_md5}</span>}
                      </div>
                    ))}
                </div>
              ))}
          </div>
        </section>
      )}

      {data.tlsCertificates.length > 0 && (
        <section>
          <h2>TLS Certificates</h2>
          <div className="cert-grid">
            {data.tlsCertificates.map((c) => (
              <div key={c.id} className={`cert-card cert-${certExpiryStatus(c.not_after)}`}>
                <div className="cert-card-header">
                  Port {c.port}
                  {c.self_signed && <span className="chip-inline">self-signed</span>}
                </div>
                <div>
                  <strong>CN:</strong> {c.subject_cn || "-"}
                </div>
                <div className="host-meta">
                  <strong>Issuer:</strong> {c.issuer_cn || "-"}
                </div>
                {c.san_list && c.san_list.length > 0 && (
                  <div className="host-meta">
                    <strong>SANs:</strong> {c.san_list.join(", ")}
                  </div>
                )}
                <div className="host-meta">
                  {c.not_before && formatDateOnly(c.not_before, me.preferences)} &ndash;{" "}
                  {c.not_after && formatDateOnly(c.not_after, me.preferences)}
                  {" "}
                  <span className={`expiry-label expiry-${certExpiryStatus(c.not_after)}`}>
                    {certExpiryLabel(c.not_after)}
                  </span>
                </div>
                {c.signature_algorithm && <div className="host-meta">{c.signature_algorithm}</div>}
                {(c.tls_version || c.cipher_suite) && (
                  <div className="host-meta">
                    {[c.tls_version, c.cipher_suite].filter(Boolean).join(" · ")}
                  </div>
                )}
                {c.key_algorithm && (
                  <div className="host-meta">
                    {c.key_algorithm}
                    {c.key_bits ? ` ${c.key_bits}-bit` : ""}
                  </div>
                )}
                <div className="fingerprint">SHA256:{c.fingerprint_sha256}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {data.screenshots.length > 0 && (
        <section>
          <h2>Screenshots</h2>
          <div className="screenshot-grid">
            {data.screenshots.map((s, i) => (
              <div key={s.id} className="screenshot-card">
                <button
                  className="screenshot-thumb-button"
                  onClick={() => setLightbox({ items: screenshotItems, index: i })}
                >
                  <img
                    className="screenshot-thumb"
                    src={`/api/screenshots/${s.id}/image`}
                    alt={s.page_title ?? s.url}
                    loading="lazy"
                  />
                </button>
                <div>
                  {s.url} (Port {s.port})
                </div>
                {s.page_title && <div className="host-meta">{s.page_title}</div>}
                <div className="host-meta">{formatDateTime(s.captured_at, me.preferences)}</div>
                {s.tls_protocol && (
                  <div className="host-meta">
                    {s.tls_protocol} ({s.tls_cipher}) · {s.tls_subject}
                    {s.tls_valid_to && ` · valid until ${formatDateOnly(s.tls_valid_to, me.preferences)}`}
                  </div>
                )}
                {s.technologies && s.technologies.length > 0 && (
                  <div className="tech-badges">
                    {s.technologies.map((t) => (
                      <span key={t} className="tech-badge">
                        {t}
                      </span>
                    ))}
                  </div>
                )}
                {s.headers?.Server && <div className="host-meta">Server: {s.headers.Server}</div>}
                {s.headers?.["X-Powered-By"] && (
                  <div className="host-meta">X-Powered-By: {s.headers["X-Powered-By"]}</div>
                )}
                {s.headers && Object.keys(s.headers).length > 0 && (
                  <details className="headers-details">
                    <summary>Response headers ({Object.keys(s.headers).length})</summary>
                    <ul className="headers-list">
                      {Object.entries(s.headers).map(([key, value]) => (
                        <li key={key}>
                          <strong>{key}:</strong> {value}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                {s.ocr_text && (
                  <details className="headers-details">
                    <summary>OCR text</summary>
                    <p className="ocr-text">{s.ocr_text}</p>
                  </details>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {data.rdpScreenshots.length > 0 && (
        <section>
          <h2>RDP Screenshots</h2>
          <div className="screenshot-grid">
            {data.rdpScreenshots.map((s, i) => (
              <div key={s.id} className="screenshot-card">
                <button
                  className="screenshot-thumb-button"
                  onClick={() => setLightbox({ items: rdpScreenshotItems, index: i })}
                >
                  <img
                    className="screenshot-thumb"
                    src={`/api/rdp-screenshots/${s.id}/image`}
                    alt={`RDP Port ${s.port}`}
                    loading="lazy"
                  />
                </button>
                <div>Port {s.port}</div>
                <div className="host-meta">{formatDateTime(s.captured_at, me.preferences)}</div>
                {s.ocr_text && (
                  <details className="headers-details">
                    <summary>OCR text</summary>
                    <p className="ocr-text">{s.ocr_text}</p>
                  </details>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <section>
        <h2>History</h2>
        <div className="timeline">
          {historyGroups.map((run) => (
            <div key={run.scanJobId} className="timeline-entry">
              <div className="timeline-dot" />
              <div className="timeline-body">
                <div className="timeline-time">
                  {formatDateTime(run.observedAt, me.preferences)}
                  {run.scannerAgentName && ` · ${run.scannerAgentName}`}
                </div>
                <div className="timeline-ports">
                  {run.ports.map((p, i) => (
                    <span key={i} className={`port-chip port-chip-${p.state}`}>
                      {p.port}
                      {p.service_name ? `/${p.service_name}` : ""} ({p.state})
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {(data.comments.length > 0 || canEdit) && (
        <section>
          <h2>Comments</h2>
          {data.comments.length > 0 && (
            <ul className="comment-list">
              {data.comments.map((c) => (
                <li key={c.id} className="comment">
                  <div className="comment-meta">
                    <strong>{c.author}</strong> · {formatDateTime(c.created_at, me.preferences)}
                    {isAdmin && (
                      <button className="link-button comment-delete" onClick={() => handleDeleteComment(c.id)}>
                        delete
                      </button>
                    )}
                  </div>
                  <p className="banner-text">{c.body}</p>
                </li>
              ))}
            </ul>
          )}
          {canEdit && (
            <form className="comment-form" onSubmit={handleAddComment}>
              <textarea
                className="notes-textarea"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                rows={3}
                placeholder="Add a comment, e.g. owner, ticket references, false-positive confirmations..."
              />
              <button type="submit" disabled={!newComment.trim()}>
                Add comment
              </button>
            </form>
          )}
        </section>
      )}

      {lightbox && (
        <Lightbox items={lightbox.items} initialIndex={lightbox.index} onClose={() => setLightbox(null)} />
      )}
    </div>
  );
}

function groupHistoryByScan(history: HostDetailData["history"]) {
  const groups = new Map<
    string,
    { scanJobId: string; observedAt: string; scannerAgentName: string | null; ports: HostDetailData["history"] }
  >();
  for (const h of history) {
    const existing = groups.get(h.scan_job_id);
    if (existing) {
      existing.ports.push(h);
      if (h.observed_at > existing.observedAt) existing.observedAt = h.observed_at;
    } else {
      groups.set(h.scan_job_id, {
        scanJobId: h.scan_job_id,
        observedAt: h.observed_at,
        scannerAgentName: h.scanner_agent_name,
        ports: [h],
      });
    }
  }
  return Array.from(groups.values()).sort((a, b) => (a.observedAt < b.observedAt ? 1 : -1));
}

interface HostChanges {
  newlyOpen: HostDetailData["history"];
  newlyClosed: HostDetailData["history"];
  serviceChanged: Array<{ port: number; from: string; to: string }>;
}

// Compares the two most recent scan runs for this host (by port number -
// history doesn't carry protocol) to surface what changed since the
// previous scan. Returns null if there's no previous scan to compare
// against yet.
function computeChanges(groups: ReturnType<typeof groupHistoryByScan>): HostChanges | null {
  if (groups.length < 2) return null;
  const [latest, previous] = groups;
  const latestByPort = new Map(latest.ports.map((p) => [p.port, p]));
  const previousByPort = new Map(previous.ports.map((p) => [p.port, p]));

  const newlyOpen: HostDetailData["history"] = [];
  const newlyClosed: HostDetailData["history"] = [];
  const serviceChanged: Array<{ port: number; from: string; to: string }> = [];

  for (const [port, p] of latestByPort) {
    const prev = previousByPort.get(port);
    if (p.state === "open" && prev?.state !== "open") {
      newlyOpen.push(p);
    } else if (p.state === "open" && prev?.state === "open" && (prev.service_name ?? "") !== (p.service_name ?? "")) {
      serviceChanged.push({ port, from: prev.service_name || "unknown", to: p.service_name || "unknown" });
    }
  }
  for (const [port, p] of previousByPort) {
    const cur = latestByPort.get(port);
    if (p.state === "open" && cur?.state !== "open") {
      newlyClosed.push(p);
    }
  }

  return { newlyOpen, newlyClosed, serviceChanged };
}
