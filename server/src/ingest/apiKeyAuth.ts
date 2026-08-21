import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import { db } from "../db";
import { logger } from "../logger";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      scannerAgentId?: string;
      scannerAgentName?: string;
    }
  }
}

export function hashApiKey(key: string): string {
  return crypto.createHash("sha256").update(key, "utf8").digest("hex");
}

// Plain string ops instead of /^Bearer\s+(.+)$/i - that regex was
// vulnerable to polynomial ReDoS on attacker-controlled header input: \s+
// and .+ overlap on whitespace characters, so a header engineered to fail
// the match only at the very end (confirmed by testing - e.g. a long run
// of spaces followed by a newline) forces the engine to backtrack through
// every possible split between the two quantifiers before giving up,
// O(n^2) in the header length. Shared by tokenAuth.ts for the same reason.
export function parseBearerToken(header: string): string | null {
  const prefix = "bearer";
  if (header.length <= prefix.length || header.slice(0, prefix.length).toLowerCase() !== prefix) {
    return null;
  }
  const rest = header.slice(prefix.length);
  const afterLeadingSpace = rest.trimStart();
  if (afterLeadingSpace.length === rest.length) return null; // no whitespace after "Bearer"
  const token = afterLeadingSpace.trimEnd();
  return token.length > 0 ? token : null;
}

// Parses the X-Scanner-Submit-Queue-Pending header (see client.go's
// setAuthHeaders) into a non-negative integer, or null for "unknown" -
// covers a missing header (an un-upgraded scanner build), a malformed
// value, and a negative number (never legitimately sent, but a header is
// still attacker-influenceable input from an authenticated-but-untrusted
// source, so it's validated rather than stored as-is).
export function parseSubmitQueuePendingHeader(header: string | undefined): number | null {
  if (header === undefined) return null;
  const n = parseInt(header, 10);
  return Number.isNaN(n) || n < 0 ? null : n;
}

// When the scanner's nuclei template tree was last written (RFC3339).
// Absent means "unknown" - nuclei isn't installed, or the templates were
// never fetched - which is deliberately distinct from a very old date,
// and only ever overwritten with a real value, never cleared by a
// scanner build that doesn't send it. A future-dated value is rejected as
// a clock problem rather than recorded, since "updated tomorrow" would
// display as permanently fresh.
export function parseNucleiTemplatesUpdatedHeader(header: string | undefined, now: Date = new Date()): Date | null {
  if (header === undefined) return null;
  const parsed = new Date(header);
  if (Number.isNaN(parsed.getTime())) return null;
  if (parsed.getTime() > now.getTime() + 60_000) return null;
  return parsed;
}

// Plain X.Y.Z numeric compare - same "no pre-release/build-metadata
// suffix" assumption as its independent counterparts in
// scannerUpdate/githubSync.ts, ScannerAgents.tsx, and the scanner's own
// internal/updater - kept as its own tiny copy rather than a shared
// import for the same reason those three already are.
function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

export async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const providedKey = parseBearerToken(header);
  if (!providedKey) {
    logger.warn({ event: "auth.api_key_missing", source_ip: req.ip, path: req.path }, "Ingest request without bearer api key");
    res.status(401).json({ error: "missing bearer api key" });
    return;
  }

  const providedHash = hashApiKey(providedKey);
  const agent = await db
    .selectFrom("scanner_agents")
    .select(["id", "name", "api_key_hash", "update_request_status"])
    .where("api_key_hash", "=", providedHash)
    .where("revoked_at", "is", null)
    .executeTakeFirst();

  if (!agent) {
    logger.warn({ event: "auth.api_key_invalid", source_ip: req.ip, path: req.path }, "Ingest request with invalid or revoked api key");
    res.status(401).json({ error: "invalid api key" });
    return;
  }

  req.scannerAgentId = agent.id;
  req.scannerAgentName = agent.name;
  // Sent by the scanner on every ingest request (see client.go's
  // setAuthHeaders) - recorded alongside last_seen_at/last_seen_ip so the
  // dashboard's Scanner Agents page can show which version is actually
  // running, not just when it was last seen.
  const reportedVersion = req.header("x-scanner-version");
  // Same piggyback-on-every-request mechanism as the version header
  // above, reporting internal/submitqueue's current backlog size for
  // this scanner (see Fleet Health's "Retry Queue Backlog" card).
  const reportedPending = parseSubmitQueuePendingHeader(req.header("x-scanner-submit-queue-pending"));
  const reportedTemplatesUpdated = parseNucleiTemplatesUpdatedHeader(req.header("x-scanner-nuclei-templates-updated"));

  // A scanner can end up already at (or past) the latest version while a
  // stale 'pending'/'failed' self-update request is still sitting on its
  // row - e.g. an admin fixed whatever made an update fail (a real case:
  // install.sh not granting write access to the binary's directory) and
  // rebuilt/reinstalled manually instead of re-triggering through the
  // dashboard, so the scanner's own update watcher never got the chance
  // to call PATCH /update-outcome and clear it. Left alone, "update
  // failed" would sit on the dashboard indefinitely with no way to
  // dismiss it even though the scanner is demonstrably already current -
  // its own version header is that evidence. Only bothers with the extra
  // lookup when this agent actually has update state to reconcile, since
  // that's null for the overwhelming majority of ingest requests.
  let clearStaleUpdateState = false;
  if (reportedVersion && agent.update_request_status !== null) {
    const release = await db
      .selectFrom("scanner_release_cache")
      .select("latest_version")
      .where("id", "=", 1)
      .executeTakeFirst();
    if (release?.latest_version && compareSemver(release.latest_version, reportedVersion) <= 0) {
      clearStaleUpdateState = true;
    }
  }

  await db
    .updateTable("scanner_agents")
    .set({
      last_seen_at: new Date(),
      last_seen_ip: req.ip ?? null,
      version: reportedVersion ?? null,
      submit_queue_pending: reportedPending,
      // Only written when the scanner actually reported one - an older
      // build that doesn't send the header must not wipe a value a newer
      // one previously recorded, unlike version/submit_queue_pending
      // where absence genuinely means "unknown right now".
      ...(reportedTemplatesUpdated ? { nuclei_templates_updated_at: reportedTemplatesUpdated } : {}),
      ...(clearStaleUpdateState
        ? { update_requested_at: null, update_request_status: null, update_failure_reason: null, update_attempt_count: 0 }
        : {}),
    })
    .where("id", "=", agent.id)
    .execute();

  next();
}
