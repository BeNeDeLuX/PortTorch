import { db } from "../db";

export interface AppSettings {
  requireAdminTotp: boolean;
  hostRetentionDays: number;
}

// Singleton row (id always 1), same idiom as digest_email_state /
// webserver_tls_alert_state / scanner_release_cache - deliberately a DB
// row rather than a config.ts env var, since an admin needs to flip this
// at runtime from the Settings page, not via a redeploy.
export async function getAppSettings(): Promise<AppSettings> {
  const row = await db
    .selectFrom("app_settings")
    .select(["require_admin_totp", "host_retention_days"])
    .where("id", "=", 1)
    .executeTakeFirstOrThrow();
  return { requireAdminTotp: row.require_admin_totp, hostRetentionDays: row.host_retention_days };
}

export async function setRequireAdminTotp(value: boolean): Promise<void> {
  await db.updateTable("app_settings").set({ require_admin_totp: value }).where("id", "=", 1).execute();
}

export async function setHostRetentionDays(value: number): Promise<void> {
  await db.updateTable("app_settings").set({ host_retention_days: value }).where("id", "=", 1).execute();
}
