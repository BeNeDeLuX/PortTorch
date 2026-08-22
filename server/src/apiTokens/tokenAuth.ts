import type { NextFunction, Request, Response } from "express";
import { db } from "../db";
import { logger } from "../logger";
import { hashApiKey, parseBearerToken } from "../ingest/apiKeyAuth";
import { checkApiTokenRateLimit } from "./rateLimit";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiTokenId?: string;
      apiTokenName?: string;
    }
  }
}

// Auth for the external/SOAR-facing API (server/src/integrations/routes.ts)
// - a third auth chain alongside session auth (dashboard) and scanner API
// keys (ingest), for non-interactive external callers that need read
// access plus the ability to trigger a rescan, neither of which fits the
// other two (session auth assumes an interactive browser user; scanner API
// keys are scoped to a specific scanner submitting its own scan results).
export async function tokenAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const providedToken = parseBearerToken(header);
  if (!providedToken) {
    logger.warn({ event: "auth.api_token_missing", source_ip: req.ip, path: req.path }, "API request without bearer token");
    res.status(401).json({ error: "missing bearer api token" });
    return;
  }

  const providedHash = hashApiKey(providedToken);
  const token = await db
    .selectFrom("api_tokens")
    .select(["id", "name"])
    .where("token_hash", "=", providedHash)
    .where("revoked_at", "is", null)
    // null expires_at means "never expires" - same "absence means
    // default-allow" idiom as scan_excludes.scanner_agent_id IS NULL.
    .where((eb) => eb.or([eb("expires_at", "is", null), eb("expires_at", ">", new Date())]))
    .executeTakeFirst();

  if (!token) {
    logger.warn({ event: "auth.api_token_invalid", source_ip: req.ip, path: req.path }, "API request with invalid or revoked token");
    res.status(401).json({ error: "invalid or revoked api token" });
    return;
  }

  // After authentication, so an unauthenticated caller can never consume
  // a real token's budget, and before last_used_at/the route itself, so a
  // throttled request costs nothing but the lookup.
  const rate = checkApiTokenRateLimit(token.id);
  if (rate.limit > 0) {
    res.setHeader("X-RateLimit-Limit", String(rate.limit));
    res.setHeader("X-RateLimit-Remaining", String(rate.remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(rate.resetAt / 1000)));
  }
  if (!rate.allowed) {
    const retryAfter = Math.max(1, Math.ceil((rate.resetAt - Date.now()) / 1000));
    res.setHeader("Retry-After", String(retryAfter));
    logger.warn({
      event: "auth.api_token_rate_limited",
      api_token_id: token.id,
      api_token_name: token.name,
      source_ip: req.ip,
      path: req.path,
      limit: rate.limit,
    });
    res.status(429).json({ error: `rate limit exceeded (${rate.limit} requests/minute), retry in ${retryAfter}s` });
    return;
  }

  req.apiTokenId = token.id;
  req.apiTokenName = token.name;
  await db.updateTable("api_tokens").set({ last_used_at: new Date() }).where("id", "=", token.id).execute();

  next();
}
