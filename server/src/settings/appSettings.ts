import { db } from "../db";

export interface AppSettings {
  requireAdminTotp: boolean;
  hostRetentionDays: number;
  staleScanThresholdMinutes: number;
  scanQueueWarningThreshold: number;
  scanLogRetentionDays: number;
  digestEmailHourUtc: number;
  epssAlertThreshold: number;
  queueBacklogThresholdMinutes: number;
  scannerOfflineThresholdMinutes: number;
  hostDisappearedThresholdDays: number;
  networkCoverageStaleDays: number;
  smtp: SmtpSettings;
  hec: HecSettings;
}

// HTTP Event Collector (Splunk HEC and the collectors that speak its
// shape) - see hec/forwarder.ts. token is withheld from the settings API
// the same way smtp.password is.
export interface HecSettings {
  url: string | null;
  token: string | null;
  auditEnabled: boolean;
  scanLogEnabled: boolean;
  index: string | null;
  sourcetype: string | null;
  verifyTls: boolean;
}

// Same "omitted means keep the stored one" convention as SmtpSettingsInput.
export interface HecSettingsInput {
  url: string | null;
  token?: string | null;
  auditEnabled: boolean;
  scanLogEnabled: boolean;
  index: string | null;
  sourcetype: string | null;
  verifyTls: boolean;
}

export interface SmtpSettings {
  host: string | null;
  port: number;
  secure: boolean;
  user: string | null;
  password: string | null;
  from: string | null;
  // Off lets an internally hosted relay present a self-signed
  // certificate. Distinct from `secure` - see the smtp_verify_tls
  // migration.
  verifyTls: boolean;
}

// Everything an admin can change from the Settings page. password is
// optional on the way in specifically so "save without retyping the
// password" is expressible - see setSmtpSettings.
export interface SmtpSettingsInput {
  host: string | null;
  port: number;
  secure: boolean;
  user: string | null;
  password?: string | null;
  from: string | null;
  // Omitted keeps the stored value, like password - see the settings
  // route's own note on why neither is required.
  verifyTls?: boolean;
}

// Singleton row (id always 1), same idiom as digest_email_state /
// webserver_tls_alert_state / scanner_release_cache - deliberately a DB
// row rather than a config.ts env var, since an admin needs to flip this
// at runtime from the Settings page, not via a redeploy.
export async function getAppSettings(): Promise<AppSettings> {
  const row = await db
    .selectFrom("app_settings")
    .select([
      "require_admin_totp",
      "host_retention_days",
      "stale_scan_threshold_minutes",
      "scan_queue_warning_threshold",
      "scan_log_retention_days",
      "digest_email_hour_utc",
      "epss_alert_threshold",
      "queue_backlog_threshold_minutes",
      "scanner_offline_threshold_minutes",
      "host_disappeared_threshold_days",
      "network_coverage_stale_days",
      "hec_url",
      "hec_token",
      "hec_audit_enabled",
      "hec_scan_log_enabled",
      "hec_index",
      "hec_sourcetype",
      "hec_verify_tls",
      "smtp_verify_tls",
      "smtp_host",
      "smtp_port",
      "smtp_secure",
      "smtp_user",
      "smtp_password",
      "smtp_from",
    ])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  return {
    requireAdminTotp: row.require_admin_totp,
    hostRetentionDays: row.host_retention_days,
    staleScanThresholdMinutes: row.stale_scan_threshold_minutes,
    scanQueueWarningThreshold: row.scan_queue_warning_threshold,
    scanLogRetentionDays: row.scan_log_retention_days,
    digestEmailHourUtc: row.digest_email_hour_utc,
    epssAlertThreshold: row.epss_alert_threshold,
    queueBacklogThresholdMinutes: row.queue_backlog_threshold_minutes,
    scannerOfflineThresholdMinutes: row.scanner_offline_threshold_minutes,
    hostDisappearedThresholdDays: row.host_disappeared_threshold_days,
    networkCoverageStaleDays: row.network_coverage_stale_days,
    hec: {
      url: row.hec_url,
      token: row.hec_token,
      auditEnabled: row.hec_audit_enabled,
      scanLogEnabled: row.hec_scan_log_enabled,
      index: row.hec_index,
      sourcetype: row.hec_sourcetype,
      verifyTls: row.hec_verify_tls,
    },
    smtp: {
      host: row.smtp_host,
      port: row.smtp_port,
      secure: row.smtp_secure,
      user: row.smtp_user,
      password: row.smtp_password,
      from: row.smtp_from,
      verifyTls: row.smtp_verify_tls,
    },
  };
}

// An omitted password means "keep the stored one" - the Settings form
// can't prefill it (the API never returns it), so treating a blank field
// as "clear the password" would silently break working auth every time
// an admin edited, say, the sender address. Clearing is still possible,
// explicitly, by sending null.
export async function setScanLogRetentionDays(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ scan_log_retention_days: value }).where("id", "=", 1).execute();
}

export async function setDigestEmailHourUtc(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ digest_email_hour_utc: value }).where("id", "=", 1).execute();
}

export async function setEpssAlertThreshold(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ epss_alert_threshold: value }).where("id", "=", 1).execute();
}

export async function setQueueBacklogThresholdMinutes(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ queue_backlog_threshold_minutes: value }).where("id", "=", 1).execute();
}

export async function setScannerOfflineThresholdMinutes(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ scanner_offline_threshold_minutes: value }).where("id", "=", 1).execute();
}

export async function setHostDisappearedThresholdDays(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ host_disappeared_threshold_days: value }).where("id", "=", 1).execute();
}

export async function setNetworkCoverageStaleDays(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ network_coverage_stale_days: value }).where("id", "=", 1).execute();
}

export async function setHecSettings(input: HecSettingsInput): Promise<void> {
  await db
    .updateTable("app_settings")
    .set({
      hec_url: input.url,
      hec_audit_enabled: input.auditEnabled,
      hec_scan_log_enabled: input.scanLogEnabled,
      hec_index: input.index,
      hec_sourcetype: input.sourcetype,
      hec_verify_tls: input.verifyTls,
      // Omitted means "keep the stored one" - the form cannot prefill
      // what the API never returns. Same as smtp_password.
      ...(input.token === undefined ? {} : { hec_token: input.token }),
    })
    .where("id", "=", 1)
    .execute();
}

export async function setSmtpSettings(input: SmtpSettingsInput): Promise<void> {
  await db
    .updateTable("app_settings")
    .set({
      smtp_host: input.host,
      smtp_port: input.port,
      smtp_secure: input.secure,
      smtp_user: input.user,
      smtp_from: input.from,
      ...(input.verifyTls === undefined ? {} : { smtp_verify_tls: input.verifyTls }),
      ...(input.password === undefined ? {} : { smtp_password: input.password }),
    })
    .where("id", "=", 1)
    .execute();
}

export async function setRequireAdminTotp(value: boolean): Promise<void> {
  await db.updateTable("app_settings").set({ require_admin_totp: value }).where("id", "=", 1).execute();
}

export async function setHostRetentionDays(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ host_retention_days: value }).where("id", "=", 1).execute();
}

export async function setStaleScanThresholdMinutes(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ stale_scan_threshold_minutes: value }).where("id", "=", 1).execute();
}

export async function setScanQueueWarningThreshold(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ scan_queue_warning_threshold: value }).where("id", "=", 1).execute();
}
