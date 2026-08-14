async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const message =
      typeof body.error === "string" ? body.error : body.error ? JSON.stringify(body.error) : `Request failed: ${res.status}`;
    throw new Error(message);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json() as Promise<T>;
}

export interface UserPreferences {
  theme: "dark" | "light" | null;
  hostsPageSize: number | null;
  showActiveScansBanner: boolean;
  defaultScannerAgentId: string | null;
  // IANA zone name (e.g. "Europe/Berlin"); null = use the browser's own
  // local timezone. timeFormat null = locale default hour cycle (e.g.
  // en-US defaults to 12h, de-DE to 24h) - see lib/formatDate.ts.
  timezone: string | null;
  timeFormat: "h12" | "h24" | null;
  // Which --accent CSS custom property value to use (styles.css); null =
  // "orange", the default color.
  accentColor: "green" | "orange" | "blue" | null;
}

export interface Me {
  username: string;
  role: string;
  version: string;
  preferences: UserPreferences;
  // True when an admin account has no 2FA enabled while the Settings
  // page's "require 2FA for all admins" toggle is on (see
  // App.tsx's route gating and Account.tsx's banner) - always false for
  // non-admin roles, since that toggle only ever governs admin accounts.
  totpSetupRequired: boolean;
}

export interface AppSettings {
  requireAdminTotp: boolean;
}

export interface DashboardUser {
  id: number;
  username: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
  totp_enabled: boolean;
  // Which scanner agents' results this user may see - empty means
  // unrestricted (sees everything), always empty for role "admin".
  scannerAgentIds: string[];
}

export type LoginResult = Me | { requiresTotp: true };

export interface TwoFactorSetup {
  secret: string;
  otpauthUrl: string;
  qrCodeDataUrl: string;
}

export interface AuditEntry {
  id: string;
  event: string;
  actor: string | null;
  source_ip: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
  // Every id-shaped key in `details` (scanner_agent_id, host_id, ...)
  // resolved to a human name, e.g. {scanner_agent_id: "scanner-office-1"}
  // - "(deleted)" if that entity's row no longer exists. Empty object
  // when details has nothing resolvable, never null.
  resolvedNames: Record<string, string>;
}

export interface AuditListResult {
  items: AuditEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export interface HostSummary {
  id: string;
  ip: string;
  hostname: string | null;
  last_seen_at: string;
  open_port_count: number;
  thumbnail_id: string | null;
  thumbnail_kind: "http" | "rdp" | null;
  os_family: string | null;
  device_type: string | null;
  mac_address: string | null;
  mac_vendor: string | null;
  // A host's identity is (ip, scanner_agent_id), not ip alone - two
  // different scanners (different, non-interconnected networks) can each
  // have a real device at the same ip, so this is shown to tell those
  // rows apart rather than looking like a single duplicated entry.
  scanner_agent_name: string | null;
  scanner_agent_id: string | null;
  // Risk indicator, computed per host from the same cve_cache/kev_cache
  // join the Vulnerabilities page and host detail use - see
  // search/routes.ts's GET /api/hosts.
  cve_count: number;
  max_cvss_score: number | null;
  has_kev: boolean;
}

export interface HostFilters {
  q?: string;
  ports?: number[];
  services?: string[];
  tags?: string[];
  osFamily?: string;
  deviceType?: string;
  hideEmpty?: boolean;
  hasScreenshot?: boolean;
  // yyyy-mm-dd, matching <input type="date">
  lastSeenAfter?: string;
  lastSeenBefore?: string;
  scannerAgentIds?: string[];
}

export interface HostListResult {
  items: HostSummary[];
  total: number;
  page: number;
  pageSize: number;
}

export interface Facets {
  ports: Array<{ port: number; count: number }>;
  services: Array<{ service: string; count: number }>;
  tags: Array<{ tag: string; count: number }>;
  osFamilies: Array<{ osFamily: string; count: number }>;
  deviceTypes: Array<{ deviceType: string; count: number }>;
}

export interface HostDetail {
  host: {
    id: string;
    ip: string;
    hostname: string | null;
    first_seen_at: string;
    last_seen_at: string;
    os_name: string | null;
    os_family: string | null;
    os_vendor: string | null;
    device_type: string | null;
    os_accuracy: number | null;
    // Only ever set when nmap resolved the host via ARP (same local L2
    // segment as the scanner) - null for anything reached over a routed
    // hop, which is most targets in a typical internal network scan.
    mac_address: string | null;
    mac_vendor: string | null;
    scanner_agent_name: string | null;
    // Manual override - see api.setHostProbeHostname. Used by the scanner
    // instead of the bare IP for TLS SNI and the gowitness screenshot URL.
    probe_hostname: string | null;
  };
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service_name: string | null;
    service_product: string | null;
    service_version: string | null;
    extra_info: string | null;
    os_type: string | null;
    cpes: string[] | null;
    banner: string | null;
    ftp_anon_listing: string | null;
    smb_shares: string | null;
    nse_extra: Array<{ id: string; output: string }> | null;
    observed_at: string;
    vulnerabilities: CveEntry[];
  }>;
  history: Array<{
    port: number;
    state: string;
    service_name: string | null;
    observed_at: string;
    scan_job_id: string;
    scanner_agent_name: string | null;
  }>;
  screenshots: Array<{
    id: string;
    port: number;
    url: string;
    image_path: string;
    http_status: number | null;
    page_title: string | null;
    captured_at: string;
    tls_protocol: string | null;
    tls_cipher: string | null;
    tls_subject: string | null;
    tls_issuer: string | null;
    tls_valid_from: string | null;
    tls_valid_to: string | null;
    technologies: string[] | null;
    headers: Record<string, string> | null;
    ocr_text: string | null;
  }>;
  rdpScreenshots: Array<{
    id: string;
    port: number;
    image_path: string;
    captured_at: string;
    ocr_text: string | null;
  }>;
  tlsCertificates: TLSCertificate[];
  sshHostKeys: SSHHostKey[];
  tags: string[];
  comments: HostComment[];
  lastScanRequest: ScanRequest | null;
}

export interface HostComment {
  id: string;
  author: string;
  body: string;
  created_at: string;
}

export interface ScanExclude {
  id: string;
  kind: "ip" | "port" | "ip_port";
  value: string;
  // null = applies to every scanner (the inherited default)
  scanner_agent_id: string | null;
  scanner_agent_name: string | null;
  created_by: string | null;
  created_at: string;
}

export interface SavedSearch {
  id: string;
  name: string;
  filters: Record<string, string>;
  created_by: string | null;
  created_at: string;
}

export type WebhookEvent =
  | "host.new"
  | "port.opened"
  | "certificate.expiring_soon"
  | "webserver_certificate.expiring_soon"
  | "saved_search.match"
  | "vulnerability.high_epss"
  | "vulnerability.kev"
  | "digest.daily"
  | "scan.stale"
  | "scanner.update_failed"
  | "scan_queue.backlog";

export type WebhookChannelType = "webhook" | "email" | "teams";

export interface Webhook {
  id: string;
  name: string;
  channel_type: WebhookChannelType;
  url: string | null;
  email_to: string | null;
  enabled: boolean;
  events: WebhookEvent[];
  created_at: string;
}

export interface WebhookDelivery {
  id: string;
  event: string;
  success: boolean;
  status_code: number | null;
  error: string | null;
  created_at: string;
}

export interface DigestResult {
  from: string;
  to: string;
  newHosts: Array<{ id: string; ip: string; hostname: string | null; observedAt: string; scannerAgentName: string | null }>;
  changedHosts: Array<{
    id: string;
    ip: string;
    hostname: string | null;
    observedAt: string;
    scannerAgentName: string | null;
    newlyOpen: Array<{ port: number; service_name: string | null }>;
    newlyClosed: Array<{ port: number; service_name: string | null }>;
  }>;
  generatedAt: string;
}

export interface TrendsResult {
  days: number;
  since: string;
  series: Array<{
    date: string;
    newHosts: number;
    totalHosts: number;
    scans: number;
    hostsScanned: number;
    openPorts: number;
    cveMatches: number;
  }>;
}

export interface FleetVulnerability {
  host_id: string;
  host_ip: string;
  host_hostname: string | null;
  port: number;
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string;
  epss_score: number | null;
  epss_percentile: number | null;
  // CISA Known Exploited Vulnerabilities catalog membership - see
  // cve/kevSync.ts. Non-null date_added means this CVE is confirmed
  // actively exploited, a stronger signal than EPSS's predicted
  // probability.
  kev_date_added: string | null;
  kev_known_ransomware_campaign_use: string | null;
}

export interface ExpiringCertificate {
  id: string;
  host_id: string;
  host_ip: string;
  host_hostname: string | null;
  port: number;
  subject_cn: string | null;
  issuer_cn: string | null;
  not_before: string | null;
  not_after: string | null;
  self_signed: boolean;
  fingerprint_sha256: string;
}

export interface TLSCertificate {
  id: string;
  port: number;
  subject_cn: string | null;
  issuer_cn: string | null;
  san_list: string[] | null;
  not_before: string | null;
  not_after: string | null;
  fingerprint_sha256: string;
  signature_algorithm: string | null;
  self_signed: boolean;
  tls_version: string | null;
  cipher_suite: string | null;
  key_algorithm: string | null;
  key_bits: number | null;
  captured_at: string;
}

export interface SSHHostKey {
  id: string;
  port: number;
  key_type: string;
  bits: number | null;
  fingerprint_md5: string | null;
  fingerprint_sha256: string;
  captured_at: string;
}

export interface CveEntry {
  id: string;
  description: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  published: string | null;
  // EPSS (exploit prediction) - synced/cached separately from the CVSS
  // fields above, see cve/epssSync.ts; null until the sync catches up or
  // if FIRST has no scored entry for this CVE.
  epssScore: number | null;
  epssPercentile: number | null;
  // Same CISA KEV membership as FleetVulnerability above, for this CVE on
  // this host's port.
  kevDateAdded: string | null;
  kevKnownRansomwareCampaignUse: string | null;
}

export interface ScanRequest {
  id: string;
  status: "pending" | "claimed" | "completed" | "failed";
  target_spec: string;
  port_spec: string;
  created_at: string;
  claimed_at: string | null;
  completed_at: string | null;
  // True once "pending"/"claimed" has sat unchanged for longer than the
  // server's STALE_SCAN_THRESHOLD_MINUTES - usually means the target
  // scanner is offline or died mid-scan. Always false for "completed"/
  // "failed". Not present in the rescan-trigger response (only the host
  // detail response computes it).
  is_stale?: boolean;
}

export interface ScannerAgent {
  id: string;
  name: string;
  last_seen_at: string | null;
  last_seen_ip: string | null;
  version: string | null;
  created_at: string;
  revoked_at: string | null;
  // Self-update (see the "Update" button on the Scanner Agents page) -
  // update_requested_at set means an update is outstanding;
  // update_request_status is null except while pending or after
  // exhausting its retries ('failed', with update_failure_reason set).
  update_requested_at: string | null;
  update_request_status: "pending" | "failed" | null;
  update_failure_reason: string | null;
}

export interface ScannerReleaseInfo {
  latestVersion: string | null;
  latestTag: string | null;
  releaseUrl: string | null;
}

export interface ActiveScanJob {
  id: string;
  scanner_agent_id: string;
  target_spec: string;
  port_spec: string;
  started_at: string;
  scanner_agent_name: string | null;
  // True once "running" has lasted longer than the server's
  // STALE_SCAN_THRESHOLD_MINUTES - usually means the scanner process died
  // mid-scan without ever reporting completed/failed.
  is_stale: boolean;
  // Excludes (global + scoped to this job's scanner) that narrow down
  // what's actually scanned within target_spec/port_spec - applied
  // scanner-side before masscan runs, so the requested range shown above
  // isn't necessarily what's really being probed. Admin-only (excludes
  // management itself is admin-only) - undefined for other roles.
  applicable_excludes?: Array<{ kind: "ip" | "port" | "ip_port"; value: string }>;
  // True only for jobs from a long-running "serve" process - see
  // ScanJobsTable.cancellable (server/src/db/types.ts) for why only those
  // can actually be stopped.
  cancellable: boolean;
  // True once an operator has clicked "Stop" - the job stays "running"
  // (and this stays true) until the scanner itself reports back via its
  // own completion call, since cancellation is only a request the
  // scanner's watcher notices on its next check, not immediate.
  cancel_requested: boolean;
}

export interface ScanJobProgress {
  // null until the scanner's first push after the job starts - a normal,
  // common state, not an error (see server/src/scanJobs/routes.ts).
  currentStage: string | null;
  stageDetail: string | null;
  logs: Array<{ time: string; stage: string; message: string }>;
  // true once the scanner's one-time complete-log upload (at scan
  // completion) has landed, meaning `logs` is the full log rather than
  // just the last ~100 lines of the periodic live snapshot. Always false
  // for a still-running scan.
  logsComplete: boolean;
  updatedAt: string | null;
}

export interface QueuedScanRequest {
  id: string;
  scanner_agent_id: string | null;
  scanner_agent_name: string | null;
  target_spec: string;
  port_spec: string;
  requested_by: string | null;
  created_at: string;
  host_ip: string | null;
  host_hostname: string | null;
}

export interface ScannerAgentWithKey extends ScannerAgent {
  apiKey: string;
}

export interface ApiToken {
  id: string;
  name: string;
  last_used_at: string | null;
  created_at: string;
  revoked_at: string | null;
  expires_at: string | null;
}

export interface ApiTokenWithSecret extends ApiToken {
  token: string;
}

// The webserver's own TLS listener certificate (Settings page) - not to
// be confused with TLSCertificate above, which is a *scanned host's*
// certificate captured during a scan.
export interface TlsCertificateInfo {
  subjectCN: string | null;
  issuerCN: string | null;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  selfSigned: boolean;
  expired: boolean;
}

// A scan-profile pick - which NSE scripts a scan actually runs. "default"
// is today's unchanged hardcoded list, "all_safe" is a broader,
// still-safe nmap category (both resolved entirely scanner-side, see
// CLAUDE.md's Scan Profiles section - the webserver never needs to know
// their contents), "custom" points at a named, admin-managed ScanProfile.
export type NSEProfileSelection = { kind: "default" } | { kind: "all_safe" } | { kind: "custom"; profileId: string };

export interface ScanProfile {
  id: string;
  name: string;
  nse_scripts: string[];
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface Schedule {
  id: string;
  scanner_agent_id: string;
  target_spec: string;
  port_spec: string;
  schedule_type: "interval" | "cron" | "once";
  interval_minutes: number | null;
  cron_expression: string | null;
  run_at: string | null;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  created_by: string | null;
  created_at: string;
  scanner_agent_name: string | null;
  nse_profile: "default" | "all_safe" | "custom";
  nse_scripts: string[] | null;
  nse_profile_label: string | null;
}

export interface ScanHistoryEntry {
  id: string;
  target_spec: string;
  port_spec: string;
  status: "completed" | "failed" | "cancelled";
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  scanner_agent_name: string | null;
  hosts_scanned: number;
  open_ports_found: number;
  screenshots: number;
  rdp_screenshots: number;
  tls_certificates: number;
}

export interface ScanHistoryResult {
  items: ScanHistoryEntry[];
  total: number;
  page: number;
  pageSize: number;
}

function hostsQueryString(filters: HostFilters, page?: number, pageSize?: number): string {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.ports?.length) params.set("port", filters.ports.join(","));
  if (filters.services?.length) params.set("service", filters.services.join(","));
  if (filters.tags?.length) params.set("tag", filters.tags.join(","));
  if (filters.osFamily) params.set("osFamily", filters.osFamily);
  if (filters.deviceType) params.set("deviceType", filters.deviceType);
  if (filters.hideEmpty) params.set("hideEmpty", "true");
  if (filters.hasScreenshot) params.set("hasScreenshot", "true");
  if (filters.lastSeenAfter) params.set("lastSeenAfter", filters.lastSeenAfter);
  if (filters.lastSeenBefore) params.set("lastSeenBefore", filters.lastSeenBefore);
  if (filters.scannerAgentIds?.length) params.set("scannerAgentId", filters.scannerAgentIds.join(","));
  if (page && page > 1) params.set("page", String(page));
  if (pageSize) params.set("pageSize", String(pageSize));
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export type HostsExportDetail = "host" | "port";

// selectedIds, when non-empty, scopes the export to exactly those hosts
// (still AND'd with allowedScannerAgentIds server-side, see
// search/routes.ts's HostFilterParams.ids) rather than every host the
// current filters match - the Dashboard's "export selected" option.
// Same "plain <a href download>" export pattern as hostsExportUrl below -
// exports every entry matching the current q/from/until filters, not
// just the current page (no page/pageSize passed).
export function auditExportUrl(
  q: string,
  from: string,
  until: string,
  events: string[] = [],
  actors: string[] = []
): string {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (from) params.set("from", from);
  if (until) params.set("until", until);
  if (events.length) params.set("events", events.join(","));
  if (actors.length) params.set("actors", actors.join(","));
  const qs = params.toString();
  return `/api/audit/export.csv${qs ? `?${qs}` : ""}`;
}

export function hostsExportUrl(filters: HostFilters, detail: HostsExportDetail = "host", selectedIds?: string[]): string {
  const qs = hostsQueryString(filters);
  let url = `/api/hosts/export.csv${qs}${qs ? "&" : "?"}detail=${detail}`;
  if (selectedIds?.length) url += `&ids=${selectedIds.join(",")}`;
  return url;
}

export function hostsExportJsonUrl(filters: HostFilters, selectedIds?: string[]): string {
  const qs = hostsQueryString(filters);
  let url = `/api/hosts/export.json${qs}`;
  if (selectedIds?.length) url += `${qs ? "&" : "?"}ids=${selectedIds.join(",")}`;
  return url;
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResult>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  verifyTotp: (code: string) =>
    request<Me>("/auth/login/verify-totp", { method: "POST", body: JSON.stringify({ code }) }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  me: () => request<Me>("/auth/me"),
  updatePreferences: (patch: Partial<UserPreferences>) =>
    request<UserPreferences>("/auth/preferences", { method: "PATCH", body: JSON.stringify(patch) }),
  twoFactorStatus: () => request<{ enabled: boolean }>("/auth/2fa/status"),
  twoFactorSetup: () => request<TwoFactorSetup>("/auth/2fa/setup", { method: "POST" }),
  twoFactorConfirm: (code: string) =>
    request<{ recoveryCodes: string[] }>("/auth/2fa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  twoFactorDisable: (password: string) =>
    request<void>("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password }) }),
  regenerateRecoveryCodes: (code: string) =>
    request<{ recoveryCodes: string[] }>("/auth/2fa/recovery-codes/regenerate", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),
  resetUserTwoFactor: (id: number) => request<void>(`/api/users/${id}/reset-2fa`, { method: "POST" }),
  hosts: (filters: HostFilters, page?: number, pageSize?: number) =>
    request<HostListResult>(`/api/hosts${hostsQueryString(filters, page, pageSize)}`),
  // Scoped to the current filters server-side (e.g. a keyword search
  // narrows the Ports/Services/... counts down to matching hosts) - same
  // query-string builder as the host list itself, so the two can't drift.
  facets: (filters: HostFilters = {}) => request<Facets>(`/api/hosts/facets${hostsQueryString(filters)}`),
  allPortFacets: (filters: HostFilters = {}) => request<Facets["ports"]>(`/api/hosts/facets/ports${hostsQueryString(filters)}`),
  host: (id: string) => request<HostDetail>(`/api/hosts/${id}`),
  rescan: (id: string, profile: NSEProfileSelection = { kind: "default" }) =>
    request<ScanRequest>(`/api/hosts/${id}/rescan`, { method: "POST", body: JSON.stringify({ profile }) }),
  dismissRescan: (id: string) => request<void>(`/api/hosts/${id}/rescan/dismiss`, { method: "POST" }),
  addHostTag: (id: string, tag: string) =>
    request<{ tag: string }>(`/api/hosts/${id}/tags`, { method: "POST", body: JSON.stringify({ tag }) }),
  removeHostTag: (id: string, tag: string) =>
    request<void>(`/api/hosts/${id}/tags/${encodeURIComponent(tag)}`, { method: "DELETE" }),
  setHostProbeHostname: (id: string, hostname: string | null) =>
    request<{ probe_hostname: string | null }>(`/api/hosts/${id}/probe-hostname`, {
      method: "PATCH",
      body: JSON.stringify({ hostname }),
    }),
  addHostComment: (id: string, body: string) =>
    request<HostComment>(`/api/hosts/${id}/comments`, { method: "POST", body: JSON.stringify({ body }) }),
  deleteHostComment: (id: string, commentId: string) =>
    request<void>(`/api/hosts/${id}/comments/${commentId}`, { method: "DELETE" }),

  expiringCertificates: () => request<ExpiringCertificate[]>("/api/certificates"),
  vulnerabilities: () => request<FleetVulnerability[]>("/api/vulnerabilities"),
  digest: (from: string, to: string) =>
    request<DigestResult>(`/api/digest?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`),
  trends: (days: number, scannerAgentIds: string[] = []) =>
    request<TrendsResult>(
      `/api/trends?days=${days}${scannerAgentIds.length ? `&scannerAgentId=${scannerAgentIds.join(",")}` : ""}`
    ),
  audit: (
    page = 1,
    pageSize = 50,
    q = "",
    from = "",
    until = "",
    events: string[] = [],
    actors: string[] = []
  ) =>
    request<AuditListResult>(
      `/api/audit?page=${page}&pageSize=${pageSize}${q ? `&q=${encodeURIComponent(q)}` : ""}${
        from ? `&from=${from}` : ""
      }${until ? `&until=${until}` : ""}${events.length ? `&events=${events.join(",")}` : ""}${
        actors.length ? `&actors=${actors.join(",")}` : ""
      }`
    ),
  auditEvents: () => request<string[]>("/api/audit/events"),
  auditActors: () => request<string[]>("/api/audit/actors"),

  agents: () => request<ScannerAgent[]>("/api/agents"),
  latestScannerRelease: () => request<ScannerReleaseInfo>("/api/agents/latest-release"),
  requestScannerUpdate: (id: string) => request<void>(`/api/agents/${id}/request-update`, { method: "POST" }),
  activeScanJobs: () => request<ActiveScanJob[]>("/api/scan-jobs/active"),
  scanJobProgress: (id: string) => request<ScanJobProgress>(`/api/scan-jobs/${id}/progress`),
  scanQueue: () => request<QueuedScanRequest[]>("/api/scan-jobs/queue"),
  dismissScanJob: (id: string) => request<void>(`/api/scan-jobs/${id}/dismiss`, { method: "POST" }),
  cancelScanJob: (id: string) => request<void>(`/api/scan-jobs/${id}/cancel`, { method: "POST" }),
  cancelQueuedScanRequest: (id: string) => request<void>(`/api/scan-jobs/queue/${id}/cancel`, { method: "POST" }),
  scanHistory: (
    q: string,
    statuses: string[],
    page: number,
    pageSize: number,
    sortKey: string,
    sortDir: "asc" | "desc"
  ) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (statuses.length) params.set("status", statuses.join(","));
    if (page > 1) params.set("page", String(page));
    params.set("pageSize", String(pageSize));
    params.set("sortKey", sortKey);
    params.set("sortDir", sortDir);
    return request<ScanHistoryResult>(`/api/scan-jobs/history?${params.toString()}`);
  },
  createAgent: (name: string) =>
    request<ScannerAgentWithKey>("/api/agents", { method: "POST", body: JSON.stringify({ name }) }),
  revokeAgent: (id: string) => request<void>(`/api/agents/${id}/revoke`, { method: "POST" }),
  deleteAgent: (id: string) => request<void>(`/api/agents/${id}`, { method: "DELETE" }),

  apiTokens: () => request<ApiToken[]>("/api/api-tokens"),
  createApiToken: (name: string, expiresAt: string | null = null) =>
    request<ApiTokenWithSecret>("/api/api-tokens", { method: "POST", body: JSON.stringify({ name, expiresAt }) }),
  revokeApiToken: (id: string) => request<void>(`/api/api-tokens/${id}/revoke`, { method: "POST" }),

  schedules: () => request<Schedule[]>("/api/schedules"),
  createSchedule: (
    input: (
      | { scheduleType: "interval"; scannerAgentId: string; targetSpec: string; portSpec: string; intervalMinutes: number }
      | { scheduleType: "cron"; scannerAgentId: string; targetSpec: string; portSpec: string; cronExpression: string }
      | { scheduleType: "once"; scannerAgentId: string; targetSpec: string; portSpec: string; runAt: string }
    ) & { profile?: NSEProfileSelection }
  ) => request<{ id: string }>("/api/schedules", { method: "POST", body: JSON.stringify(input) }),
  setScheduleEnabled: (id: string, enabled: boolean) =>
    request<void>(`/api/schedules/${id}`, { method: "PATCH", body: JSON.stringify({ enabled }) }),
  updateSchedule: (
    id: string,
    patch: {
      targetSpec?: string;
      portSpec?: string;
      scannerAgentId?: string;
      intervalMinutes?: number;
      cronExpression?: string;
      runAt?: string;
      profile?: NSEProfileSelection;
    }
  ) => request<void>(`/api/schedules/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteSchedule: (id: string) => request<void>(`/api/schedules/${id}`, { method: "DELETE" }),

  scanProfiles: () => request<ScanProfile[]>("/api/scan-profiles"),
  createScanProfile: (name: string, nseScripts: string[]) =>
    request<ScanProfile>("/api/scan-profiles", { method: "POST", body: JSON.stringify({ name, nseScripts }) }),
  updateScanProfile: (id: string, patch: { name?: string; nseScripts?: string[] }) =>
    request<ScanProfile>(`/api/scan-profiles/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteScanProfile: (id: string) => request<void>(`/api/scan-profiles/${id}`, { method: "DELETE" }),

  tlsCertificate: () => request<TlsCertificateInfo>("/api/settings/tls-certificate"),
  // Bypasses request()'s JSON-only helper - a multipart body needs the
  // browser to set its own Content-Type with a boundary, which it only
  // does when Content-Type is left unset entirely.
  uploadTlsCertificate: async (certificateFile: File, privateKeyFile: File) => {
    const formData = new FormData();
    formData.append("certificate", certificateFile);
    formData.append("privateKey", privateKeyFile);
    const res = await fetch("/api/settings/tls-certificate", {
      method: "POST",
      credentials: "include",
      body: formData,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const message =
        typeof body.error === "string" ? body.error : body.error ? JSON.stringify(body.error) : `Request failed: ${res.status}`;
      throw new Error(message);
    }
    return res.json() as Promise<TlsCertificateInfo>;
  },
  appSettings: () => request<AppSettings>("/api/settings/app"),
  updateAppSettings: (patch: Partial<AppSettings>) =>
    request<AppSettings>("/api/settings/app", { method: "PATCH", body: JSON.stringify(patch) }),

  users: () => request<DashboardUser[]>("/api/users"),
  createUser: (input: { username: string; password: string; role: string; scannerAgentIds?: string[] }) =>
    request<DashboardUser>("/api/users", { method: "POST", body: JSON.stringify(input) }),
  deleteUser: (id: number) => request<void>(`/api/users/${id}`, { method: "DELETE" }),
  setUserScannerAgents: (id: number, scannerAgentIds: string[]) =>
    request<{ scannerAgentIds: string[] }>(`/api/users/${id}/scanner-agents`, {
      method: "PATCH",
      body: JSON.stringify({ scannerAgentIds }),
    }),

  webhooks: () => request<Webhook[]>("/api/webhooks"),
  createWebhook: (input: { name: string; channelType: WebhookChannelType; url?: string; emailTo?: string; events: WebhookEvent[] }) =>
    request<Webhook>("/api/webhooks", { method: "POST", body: JSON.stringify(input) }),
  setWebhookEnabled: (id: string, enabled: boolean) =>
    request<void>(`/api/webhooks/${id}`, { method: "PATCH", body: JSON.stringify({ enabled }) }),
  deleteWebhook: (id: string) => request<void>(`/api/webhooks/${id}`, { method: "DELETE" }),
  testWebhook: (id: string) => request<{ ok: boolean; status?: number; error?: string }>(`/api/webhooks/${id}/test`, { method: "POST" }),
  webhookDeliveries: (id: string) => request<WebhookDelivery[]>(`/api/webhooks/${id}/deliveries`),

  excludes: () => request<ScanExclude[]>("/api/excludes"),
  createExclude: (kind: "ip" | "port" | "ip_port", value: string, scannerAgentId: string | null) =>
    request<ScanExclude>("/api/excludes", { method: "POST", body: JSON.stringify({ kind, value, scannerAgentId }) }),
  deleteExclude: (id: string) => request<void>(`/api/excludes/${id}`, { method: "DELETE" }),

  savedSearches: () => request<SavedSearch[]>("/api/saved-searches"),
  createSavedSearch: (name: string, filters: Record<string, string>) =>
    request<SavedSearch>("/api/saved-searches", { method: "POST", body: JSON.stringify({ name, filters }) }),
  deleteSavedSearch: (id: string) => request<void>(`/api/saved-searches/${id}`, { method: "DELETE" }),
};
