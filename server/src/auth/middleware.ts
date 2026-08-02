import type { NextFunction, Request, Response } from "express";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    res.status(401).json({ error: "authentication required" });
    return;
  }
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    res.status(401).json({ error: "authentication required" });
    return;
  }
  if (req.session.role !== "admin") {
    res.status(403).json({ error: "admin role required" });
    return;
  }
  next();
}

// Roles: "admin" (everything), "operator" (read-only + trigger rescans),
// "user" (read-only). Only rescan is gated on this - every other mutating
// endpoint (tags, scanner agents, schedules, webhooks, user management)
// requires requireAdmin.
export function requireOperator(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    res.status(401).json({ error: "authentication required" });
    return;
  }
  if (req.session.role !== "admin" && req.session.role !== "operator") {
    res.status(403).json({ error: "operator or admin role required" });
    return;
  }
  next();
}
