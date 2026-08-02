import type { NextFunction, Request, Response } from "express";
import { logger } from "../logger";

/**
 * Access log for every HTTP request. Deliberately logs only metadata
 * (never headers/body - those could contain passwords or API keys).
 */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
    logger.info({
      event: "http.request",
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration_ms: Math.round(durationMs * 100) / 100,
      source_ip: req.ip,
      username: req.session?.username,
      scanner_agent_id: req.scannerAgentId,
    });
  });
  next();
}
