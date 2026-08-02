import { db } from "../db";
import { logger } from "../logger";

/**
 * Persists a security-relevant action for the in-app /audit page - a
 * separate concern from the pino stdout logging (which stays as the
 * SIEM-facing stream). Never throws: a failed audit write must not break
 * the request that triggered it.
 */
export async function recordAudit(
  event: string,
  actor: string | null | undefined,
  sourceIp: string | undefined,
  details: Record<string, unknown> = {}
): Promise<void> {
  try {
    await db
      .insertInto("audit_log")
      .values({
        event,
        actor: actor ?? null,
        source_ip: sourceIp ?? null,
        details: JSON.stringify(details),
      })
      .execute();
  } catch (err) {
    logger.warn({ event: "audit.write_failed", err: err instanceof Error ? err.message : String(err) });
  }
}
