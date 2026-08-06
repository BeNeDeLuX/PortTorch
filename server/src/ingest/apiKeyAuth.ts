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
    .select(["id", "name", "api_key_hash"])
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
  await db
    .updateTable("scanner_agents")
    .set({ last_seen_at: new Date(), last_seen_ip: req.ip ?? null, version: reportedVersion ?? null })
    .where("id", "=", agent.id)
    .execute();

  next();
}
