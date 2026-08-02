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

export async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) {
    logger.warn({ event: "auth.api_key_missing", source_ip: req.ip, path: req.path }, "Ingest request without bearer api key");
    res.status(401).json({ error: "missing bearer api key" });
    return;
  }

  const providedHash = hashApiKey(match[1]);
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
