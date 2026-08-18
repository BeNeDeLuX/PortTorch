import type { ColumnType, Generated } from "kysely";

export interface UsersTable {
  id: Generated<number>;
  username: string;
  password_hash: string;
  role: string;
  created_at: ColumnType<Date, string | undefined, never>;
  last_login_at: ColumnType<Date | null, string | undefined, string>;
  totp_secret: string | null;
  totp_enabled: ColumnType<boolean, boolean | undefined, boolean>;
  totp_recovery_codes: string[] | null;
  // Account-level defaults, set from the Account page - null means "no
  // override", i.e. fall back to the built-in default (see auth/routes.ts's
  // toPreferences). Followed across browsers/devices, unlike the existing
  // localStorage-based theme toggle/table prefs, which are per-browser.
  pref_theme: "dark" | "light" | null;
  pref_hosts_page_size: number | null;
  pref_show_active_scans_banner: ColumnType<boolean, boolean | undefined, boolean>;
  pref_default_scanner_agent_id: string | null;
  // IANA zone name (e.g. "Europe/Berlin"); null means "use the browser's
  // own local timezone", same null-means-no-override convention as the
  // other preferences here.
  pref_timezone: string | null;
  pref_time_format: "h12" | "h24" | null;
  // Which --accent CSS custom property value to use (styles.css); null
  // means "green", today's only/default color.
  pref_accent_color: "green" | "orange" | "blue" | null;
}

export interface ScannerAgentsTable {
  id: Generated<string>;
  name: string;
  api_key_hash: string;
  last_seen_at: Date | null;
  last_seen_ip: string | null;
  // Reported by the scanner on every ingest request (X-Scanner-Version
  // header) - null until a scanner built with that support has made at
  // least one request.
  version: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  revoked_at: Date | null;
  // Self-update (see src/scannerUpdate) - the webserver can never push to
  // a scanner, so this is a flag the scanner's own update watcher polls
  // for (GET /api/ingest/update-requested), mirroring scan_jobs'
  // cancel_requested_at exactly. update_request_status is null except
  // while a request is outstanding ('pending') or has exhausted its
  // retries ('failed', requiring an explicit admin re-trigger).
  update_requested_at: Date | null;
  update_request_status: "pending" | "failed" | null;
  update_failure_reason: string | null;
  update_attempt_count: ColumnType<number, number | undefined, number>;
  // Dedup state for the scan_queue.backlog webhook (see
  // webhooks/operationalAlerts.ts) - unlike most alert-dedup columns in
  // this codebase, this one is cleared back to null once the backlog
  // clears, since a queue backlog is a recurring condition, not a
  // one-time event like a certificate approaching expiry.
  queue_backlog_alert_sent_at: Date | null;
  // Reported by the scanner on every ingest request
  // (X-Scanner-Submit-Queue-Pending header, alongside version above) -
  // the current size of that scanner's local internal/submitqueue retry
  // backlog. Null until a scanner build with this support has made at
  // least one request - same "absence means unknown, not zero" reasoning
  // as version itself, so a never-reported scanner isn't shown as having
  // an empty queue.
  submit_queue_pending: number | null;
}

// Singleton (id always 1) cache of the latest published scanner-vX.Y.Z
// GitHub release - see src/scannerUpdate/githubSync.ts.
export interface ScannerReleaseCacheTable {
  id: Generated<number>;
  latest_version: string | null;
  latest_tag: string | null;
  release_url: string | null;
  synced_at: Date | null;
}

// Singleton (id always 1) alert-dedup state for the webserver's own TLS
// listener certificate - see src/settings/certExpiryAlert.ts. Keyed by
// fingerprint rather than a plain "already alerted" boolean so an
// uploaded replacement certificate (Settings page) is treated as a
// fresh, not-yet-alerted certificate even if the previous one had
// already fired.
export interface WebserverTlsAlertStateTable {
  id: Generated<number>;
  fingerprint: string | null;
  alert_sent_at: Date | null;
}

// For external, non-interactive callers (SOAR/enrichment tools) - distinct
// from scanner_agents (which authenticate a specific scanner submitting
// scan results) and from session auth (interactive dashboard users).
export interface ApiTokensTable {
  id: Generated<string>;
  name: string;
  token_hash: string;
  created_by: string | null;
  last_used_at: Date | null;
  created_at: ColumnType<Date, string | undefined, never>;
  revoked_at: Date | null;
  // Optional, set once at creation and never edited afterward - null
  // means "never expires" (the behavior for every token created before
  // this column existed). See apiTokens/tokenAuth.ts for enforcement.
  expires_at: Date | null;
}

export interface ScanJobsTable {
  id: Generated<string>;
  // null means the scanner agent that ran this job was later deleted -
  // the job itself (and everything cascading from it) is preserved as
  // read-only history rather than deleted along with the agent.
  scanner_agent_id: string | null;
  target_spec: string;
  port_spec: string;
  status: string;
  started_at: ColumnType<Date, string | undefined, never>;
  finished_at: Date | null;
  // True only for jobs created by a long-running "serve" process (its own
  // REST-triggered ad-hoc scans and queue-triggered ones) - only those can
  // actually be stopped, since only "serve" runs the concurrent watcher
  // that checks cancel_requested_at while the scan is in progress. A
  // one-shot "scan"/"menu" process has nothing polling during its single
  // blocking scan, so cancellation could never reach it.
  cancellable: ColumnType<boolean, boolean | undefined, never>;
  cancel_requested_at: ColumnType<Date | null, string | undefined, string>;
  // Dedup state for the scan.stale webhook (see
  // webhooks/operationalAlerts.ts) - fires once per row, never reset,
  // since a scan_jobs row is created fresh per scan and either finishes
  // normally or stays stuck in "running" forever.
  stale_alert_sent_at: Date | null;
}

// Live-ish progress pushed by the scanner itself while a scan runs (see
// "Scan pipeline" in CLAUDE.md) - separate from ScanJobsTable since this
// updates far more often and holds nothing worth keeping once the job
// finishes. current_stage/stage_detail are null until the scanner's first
// push; recent_logs is a capped rolling buffer (scanner-side cap, not
// enforced again here - the scanner already sends at most maxLogLines).
export interface ScanJobProgressTable {
  scan_job_id: string;
  current_stage: string | null;
  stage_detail: string | null;
  recent_logs: ColumnType<ScanProgressLogLine[], string, string>;
  updated_at: ColumnType<Date, string | undefined, string>;
}

export interface ScanProgressLogLine {
  time: string;
  stage: string;
  message: string;
}

// The complete progress log for a finished scan, uploaded once at
// Close() (see scanner/internal/progress/tracker.go and
// CLAUDE.md's "Scan progress" section) - unlike ScanJobProgressTable's
// recent_logs, this isn't capped to the scanner's small periodic-push
// buffer, only to its much higher one-time-upload ceiling.
export interface ScanJobFullLogTable {
  scan_job_id: string;
  logs: ColumnType<ScanProgressLogLine[], string, string>;
  created_at: ColumnType<Date, string | undefined, string>;
}

export interface HostsTable {
  id: Generated<string>;
  ip: string;
  // Which scanner reported this host - part of its identity, not just
  // metadata: two different scanners (different, non-interconnected
  // networks) can each have a real device at the same ip, so identity is
  // (ip, scanner_agent_id), not ip alone. Null only ever means the
  // scanner that originally reported this host has since been deleted
  // (ON DELETE SET NULL) - never true for a host as of its own ingest.
  scanner_agent_id: string | null;
  hostname: string | null;
  os_name: string | null;
  os_family: string | null;
  os_vendor: string | null;
  device_type: string | null;
  os_accuracy: number | null;
  // From nmap's ARP resolution - only ever populated when the host is on
  // the scanner's own local L2 segment (see pipeline/nmap.go's
  // applyMACAddress); null for anything reached over a routed hop, which
  // is most targets in a typical internal network scan.
  mac_address: string | null;
  mac_vendor: string | null;
  // Manual override, never written by the scan pipeline itself (unlike
  // hostname, which nmap's own PTR lookup overwrites every scan) - set by
  // an admin/operator on the Host Detail page when the discovered IP alone
  // can't reach the right vhost (SNI-based routing, e.g. nginx rejecting a
  // TLS handshake whose SNI doesn't match any server_name). Used instead
  // of the bare IP for the TLS certificate probe's SNI and the gowitness
  // screenshot URL - see pipeline/tlscert.go and orchestrator.go.
  probe_hostname: string | null;
  first_seen_at: ColumnType<Date, string | undefined, never>;
  last_seen_at: ColumnType<Date, string | undefined, string>;
}

export interface HostPortObservationsTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
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
  // Both best-effort NSE script output, populated only when the target
  // allows an anonymous/guest session at all (see scanner's nmap.go) -
  // null otherwise, same "absence means access was denied, not an error"
  // reasoning as banner itself.
  ftp_anon_listing: string | null;
  smb_shares: string | null;
  // Every other NSE script result nmap produced for this port that
  // doesn't get its own dedicated column above (nfs-showmount,
  // rsync-list-modules, ldap-rootdse, the open-database checks - see
  // scanner's nmap.go PortResult.ExtraScripts) - null when none produced
  // output, same "absence means access was denied, not an error"
  // reasoning as banner/ftp_anon_listing/smb_shares.
  nse_extra: ColumnType<NSEScriptEntry[] | null, string | null | undefined, string | null>;
  observed_at: ColumnType<Date, string | undefined, never>;
}

export interface NSEScriptEntry {
  id: string;
  output: string;
}

export interface CurrentHostPortsTable extends HostPortObservationsTable {}

export interface ScreenshotsTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
  port: number;
  url: string;
  image_path: string;
  http_status: number | null;
  page_title: string | null;
  captured_at: ColumnType<Date, string | undefined, never>;
  tls_protocol: string | null;
  tls_cipher: string | null;
  tls_subject: string | null;
  tls_issuer: string | null;
  tls_valid_from: Date | null;
  tls_valid_to: Date | null;
  technologies: string[] | null;
  // Stored as jsonb; inserted as a JSON string, read back as a parsed
  // object (node-postgres parses jsonb columns on select automatically).
  headers: ColumnType<Record<string, string> | null, string | null, string | null>;
  // Extracted by the scanner via Tesseract (pipeline/ocr.go) - best-effort,
  // null if tesseract wasn't installed on the scanner or recognition failed.
  ocr_text: string | null;
}

export interface RdpScreenshotsTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
  port: number;
  image_path: string;
  captured_at: ColumnType<Date, string | undefined, never>;
  ocr_text: string | null;
}

export interface ScanSchedulesTable {
  id: Generated<string>;
  scanner_agent_id: string;
  target_spec: string;
  port_spec: string;
  // Exactly one of interval_minutes/cron_expression/run_at is set,
  // matching schedule_type - enforced by scan_schedules_type_fields_check,
  // not just convention.
  schedule_type: ColumnType<
    "interval" | "cron" | "once",
    "interval" | "cron" | "once" | undefined,
    "interval" | "cron" | "once"
  >;
  interval_minutes: number | null;
  cron_expression: string | null;
  run_at: ColumnType<Date | null, string | null | undefined, string | null>;
  enabled: ColumnType<boolean, boolean | undefined, boolean>;
  next_run_at: ColumnType<Date, string | undefined, string>;
  last_run_at: ColumnType<Date | null, string | undefined, string>;
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  // Scan-profile pick (see scanProfiles/resolve.ts's resolveNSEProfile) -
  // a resolved snapshot at creation/last-edit time, never a live join
  // against scan_profiles. nse_scripts is only ever set for 'custom'.
  nse_profile: ColumnType<"default" | "all_safe" | "custom", "default" | "all_safe" | "custom" | undefined, "default" | "all_safe" | "custom">;
  nse_scripts: string[] | null;
  nse_profile_label: string | null;
  // Same resolved-snapshot shape as nse_profile above, for the
  // independent nuclei web-vulnerability-scanning stage - see
  // nucleiProfiles/resolve.ts's resolveNucleiProfile. nuclei_tags is only
  // ever set for 'custom'.
  nuclei_profile: ColumnType<"off" | "safe" | "custom", "off" | "safe" | "custom" | undefined, "off" | "safe" | "custom">;
  nuclei_tags: string[] | null;
  nuclei_profile_label: string | null;
  // NULL = use the scanner's own configured masscanRate (see the
  // scan_masscan_rate migration).
  masscan_rate: number | null;
}

export interface ScanRequestsTable {
  id: Generated<string>;
  // null means the scanner agent this request was queued for was later
  // deleted - the request itself is preserved as read-only history
  // rather than deleted along with the agent.
  scanner_agent_id: string | null;
  host_id: string | null;
  target_spec: string;
  port_spec: string;
  status: ColumnType<string, string | undefined, string>;
  scan_job_id: string | null;
  requested_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  claimed_at: ColumnType<Date | null, string | undefined, string>;
  completed_at: ColumnType<Date | null, string | undefined, string>;
  // Same scan-profile snapshot shape as ScanSchedulesTable above.
  nse_profile: ColumnType<"default" | "all_safe" | "custom", "default" | "all_safe" | "custom" | undefined, "default" | "all_safe" | "custom">;
  nse_scripts: string[] | null;
  nse_profile_label: string | null;
  // Same nuclei-profile snapshot shape as ScanSchedulesTable above.
  nuclei_profile: ColumnType<"off" | "safe" | "custom", "off" | "safe" | "custom" | undefined, "off" | "safe" | "custom">;
  nuclei_tags: string[] | null;
  nuclei_profile_label: string | null;
  // Same NULL-means-scanner-default semantics as ScanSchedulesTable's own
  // column; snapshotted from the schedule when scheduler.ts spawns a run.
  masscan_rate: number | null;
}

export interface ScanProfilesTable {
  id: Generated<string>;
  name: string;
  nse_scripts: string[];
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  updated_at: ColumnType<Date, string | undefined, string>;
}

export interface NucleiProfilesTable {
  id: Generated<string>;
  name: string;
  tags: string[];
  severities: string[];
  excluded_tags: string[];
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  updated_at: ColumnType<Date, string | undefined, string>;
}

export interface NucleiFindingsTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
  port: number;
  template_id: string;
  name: string;
  severity: string;
  matched_at: string;
  description: string | null;
  reference: string[] | null;
  tags: string[] | null;
  curl_command: string | null;
  observed_at: ColumnType<Date, string | undefined, never>;
}

// Triage state for a security finding - see the finding_triage migration
// for why this is its own table rather than a column on the finding.
// Absence of a row means "open"/untriaged; only deliberate exceptions are
// stored here.
export type TriageState = "false_positive" | "accepted_risk" | "fixed";

export interface FindingTriageTable {
  id: Generated<string>;
  kind: "cve" | "nuclei";
  host_id: string;
  // Exactly one identity shape is set, per the table's own CHECK: cve_id
  // for kind='cve', template_id+matched_at for kind='nuclei'.
  cve_id: string | null;
  template_id: string | null;
  matched_at: string | null;
  state: TriageState;
  note: string | null;
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
  updated_at: ColumnType<Date, string | undefined, string>;
}

export interface TlsCertificatesTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
  port: number;
  subject_cn: string | null;
  issuer_cn: string | null;
  san_list: string[] | null;
  not_before: Date | null;
  not_after: Date | null;
  fingerprint_sha256: string;
  signature_algorithm: string | null;
  self_signed: ColumnType<boolean, boolean | undefined, boolean>;
  tls_version: string | null;
  cipher_suite: string | null;
  key_algorithm: string | null;
  key_bits: number | null;
  expiry_alert_sent_at: Date | null;
  captured_at: ColumnType<Date, string | undefined, never>;
}

export interface SshHostKeysTable {
  id: Generated<string>;
  host_id: string;
  scan_job_id: string;
  port: number;
  key_type: string;
  bits: number | null;
  fingerprint_md5: string | null;
  fingerprint_sha256: string;
  captured_at: ColumnType<Date, string | undefined, never>;
}

export interface HostTagsTable {
  id: Generated<string>;
  host_id: string;
  tag: string;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface HostCommentsTable {
  id: Generated<string>;
  host_id: string;
  author: string;
  body: string;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface SavedSearchesTable {
  id: Generated<string>;
  name: string;
  // Stored as jsonb; inserted as a JSON string, read back as a parsed
  // object (same pattern as screenshots.headers/audit_log.details).
  filters: ColumnType<Record<string, unknown>, string, string>;
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface SavedSearchMatchesTable {
  saved_search_id: string;
  host_id: string;
}

// Restricts a non-admin user to only that scanner agent's results (see
// server/src/auth/scannerScope.ts) - no rows for a user = unrestricted.
export interface UserScannerAgentsTable {
  user_id: number;
  scanner_agent_id: string;
}

export interface CveEntry {
  id: string;
  description: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  published: string | null;
}

export interface CveCacheTable {
  cpe: string;
  // Stored as jsonb; inserted as a JSON string, read back as a parsed
  // array (same pattern as screenshots.headers/audit_log.details).
  cves: ColumnType<CveEntry[], string, string>;
  checked_at: ColumnType<Date, string | undefined, string>;
}

// Keyed by CVE id (unlike cve_cache, which is keyed by CPE) since EPSS
// scores a specific CVE, not a product/version - see src/cve/epssSync.ts.
export interface EpssCacheTable {
  cve_id: string;
  epss: number;
  percentile: number;
  checked_at: ColumnType<Date, string | undefined, string>;
  // Set once a "vulnerability.high_epss" webhook has fired for this CVE
  // (config.epssAlertThreshold) - never re-armed, so a score that
  // fluctuates around the threshold day to day doesn't re-alert on every
  // crossing, same "fire once per row" reasoning as
  // tls_certificates.expiry_alert_sent_at.
  alert_sent_at: ColumnType<Date | null, string | null | undefined, string | null>;
}

// CISA's Known Exploited Vulnerabilities catalog - keyed by CVE id like
// EpssCacheTable, for the same reason (KEV scores a specific
// vulnerability, not a product/version) - see src/cve/kevSync.ts.
export interface KevCacheTable {
  cve_id: string;
  vendor_project: string | null;
  product: string | null;
  vulnerability_name: string | null;
  date_added: ColumnType<Date | null, string | null | undefined, string | null>;
  due_date: ColumnType<Date | null, string | null | undefined, string | null>;
  known_ransomware_campaign_use: string | null;
  synced_at: ColumnType<Date, string | undefined, string>;
  // Set once a "vulnerability.kev" webhook has fired for this CVE - never
  // re-armed, same "fire once per row" reasoning as
  // EpssCacheTable.alert_sent_at.
  alert_sent_at: ColumnType<Date | null, string | null | undefined, string | null>;
}

// Singleton row (id always 1) - see migration
// 1741100000000_epss_alert_and_digest_email.js.
export interface DigestEmailStateTable {
  id: Generated<number>;
  // Read back as a JS Date (midnight UTC), not the plain "YYYY-MM-DD"
  // string it's written as - node-postgres's default parser for a `date`
  // column, confirmed by testing (see digest/emailDigest.ts's
  // toDateOnlyString, which exists specifically to normalize this).
  last_sent_date: ColumnType<Date | null, string | null | undefined, string | null>;
}

export interface ScanExcludesTable {
  id: Generated<string>;
  kind: string;
  value: string;
  // null = applies to every scanner (the inherited default); set = only
  // that one scanner, e.g. to exclude an IP that's only sensitive within
  // that specific scanner's network (private ranges commonly overlap
  // across scanners in different networks).
  scanner_agent_id: string | null;
  created_by: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface WebhooksTable {
  id: Generated<string>;
  name: string;
  // 'webhook' | 'email' | 'teams' - 'teams' shares the url column with
  // 'webhook' (both are just a POST target), only the body shape differs
  // (see webhooks/dispatch.ts's buildTeamsAdaptiveCardBody). Exactly one
  // of url/email_to is set per type, enforced by
  // webhooks_channel_type_fields_check - see migrations
  // 1741000000000_webhook_email_channel.js and
  // 1741200000000_webhook_teams_channel.js.
  channel_type: ColumnType<string, string | undefined, string>;
  url: string | null;
  // Comma-joined recipient list for an "email" channel, same convention as
  // every other comma-joined multi-value field in this app (see
  // scannerAgentId filters, port/service/tag search params).
  email_to: string | null;
  enabled: ColumnType<boolean, boolean | undefined, boolean>;
  events: string[];
  created_at: ColumnType<Date, string | undefined, never>;
}

// One row per actual delivery attempt (webhooks/dispatch.ts) - trimmed to
// the most recent rows per webhook_id at insert time, not kept forever
// like audit_log, since this is a diagnostic tail for "is this webhook
// actually working" rather than a permanent record.
export interface WebhookDeliveriesTable {
  id: Generated<string>;
  webhook_id: string;
  event: string;
  success: boolean;
  status_code: number | null;
  error: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
}

// Singleton row (id always 1) of global, admin-configurable toggles that
// don't belong to any one user's account - see settings/appSettings.ts.
export interface AppSettingsTable {
  id: Generated<number>;
  require_admin_totp: ColumnType<boolean, boolean | undefined, boolean>;
  // Was config.ts's HOST_RETENTION_DAYS env var - moved here so it's
  // live-editable from the Settings page (see retention.ts). 0 disables
  // the sweep entirely, same semantics the env var always had.
  host_retention_days: ColumnType<number, number | undefined, number>;
  // Was config.ts's staleScanThresholdMinutes env var - moved here for the
  // same reason as host_retention_days above (see lib/staleness.ts).
  stale_scan_threshold_minutes: ColumnType<number, number | undefined, number>;
  // How many pending scan_requests rows before Fleet Health's "Scan
  // Queue" card escalates to "warning" - see useFleetHealth.ts.
  scan_queue_warning_threshold: ColumnType<number, number | undefined, number>;
}

export interface AuditLogTable {
  id: Generated<string>;
  event: string;
  actor: string | null;
  source_ip: string | null;
  // Stored as jsonb; inserted as a JSON string, read back as a parsed
  // object (same pattern as screenshots.headers).
  details: ColumnType<Record<string, unknown> | null, string | null, never>;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface Database {
  users: UsersTable;
  scanner_agents: ScannerAgentsTable;
  api_tokens: ApiTokensTable;
  scan_jobs: ScanJobsTable;
  scan_job_progress: ScanJobProgressTable;
  scan_job_full_log: ScanJobFullLogTable;
  hosts: HostsTable;
  host_port_observations: HostPortObservationsTable;
  current_host_ports: CurrentHostPortsTable;
  screenshots: ScreenshotsTable;
  host_tags: HostTagsTable;
  host_comments: HostCommentsTable;
  scan_excludes: ScanExcludesTable;
  saved_searches: SavedSearchesTable;
  saved_search_matches: SavedSearchMatchesTable;
  user_scanner_agents: UserScannerAgentsTable;
  cve_cache: CveCacheTable;
  epss_cache: EpssCacheTable;
  kev_cache: KevCacheTable;
  digest_email_state: DigestEmailStateTable;
  webhooks: WebhooksTable;
  webhook_deliveries: WebhookDeliveriesTable;
  audit_log: AuditLogTable;
  rdp_screenshots: RdpScreenshotsTable;
  scan_schedules: ScanSchedulesTable;
  scan_requests: ScanRequestsTable;
  tls_certificates: TlsCertificatesTable;
  ssh_host_keys: SshHostKeysTable;
  scan_profiles: ScanProfilesTable;
  nuclei_profiles: NucleiProfilesTable;
  nuclei_findings: NucleiFindingsTable;
  finding_triage: FindingTriageTable;
  scanner_release_cache: ScannerReleaseCacheTable;
  webserver_tls_alert_state: WebserverTlsAlertStateTable;
  app_settings: AppSettingsTable;
}
