import fs from "fs";
import path from "path";
import express from "express";
import type { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { config } from "./config";
import { pgPool } from "./db";
import { logger } from "./logger";
import { requestLogger } from "./lib/requestLogger";
import { authRouter } from "./auth/routes";
import { observabilityRouter } from "./observability/routes";
import { ingestRouter } from "./ingest/routes";
import { agentsRouter } from "./agents/routes";
import { scanJobsRouter } from "./scanJobs/routes";
import { hostsRouter } from "./search/routes";
import { screenshotsRouter, rdpScreenshotsRouter } from "./screenshots/routes";
import { schedulesRouter } from "./schedules/routes";
import { adhocScansRouter } from "./adhocScans/routes";
import { certificatesRouter } from "./certificates/routes";
import { vulnerabilitiesRouter } from "./vulnerabilities/routes";
import { usersRouter } from "./users/routes";
import { digestRouter } from "./digest/routes";
import { trendsRouter } from "./trends/routes";
import { webhooksRouter } from "./webhooks/routes";
import { auditRouter } from "./audit/routes";
import { excludesRouter } from "./excludes/routes";
import { apiTokensRouter } from "./apiTokens/routes";
import { integrationsRouter } from "./integrations/routes";
import { apiDocsRouter } from "./integrations/docsRoutes";
import { savedSearchesRouter } from "./savedSearches/routes";
import { scanProfilesRouter } from "./scanProfiles/routes";
import { nucleiProfilesRouter } from "./nucleiProfiles/routes";
import { nucleiFindingsRouter } from "./nucleiFindings/routes";
import { findingTriageRouter } from "./findingTriage/routes";
import { settingsRouter } from "./settings/routes";

// Pure Express app construction, split out from index.ts so integration
// tests (see tests/integration/) can import a fully-wired app - routes,
// session, middleware - without also pulling in index.ts's process-level
// side effects (starting the HTTPS listener, generating a TLS cert, or
// starting the background schedulers/CVE-sync/retention/webhook-alert
// timers, none of which a route test wants running against a test
// database). index.ts remains the actual process entrypoint and is the
// only place those side effects happen.
export function buildApp() {
  const app = express();
  app.set("trust proxy", 1);
  app.use(helmet());
  app.use(express.json({ limit: "1mb" }));
  app.use(requestLogger);
  app.use(
    session({
      store: new (connectPgSimple(session))({ pool: pgPool, tableName: "session" }),
      secret: config.sessionSecret,
      name: "porttorch.sid",
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: true,
        httpOnly: true,
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 12,
      },
    })
  );

  // Mounted at the root, before every authenticated router: /healthz must
  // be reachable by infrastructure that has no session and no token, and
  // /metrics carries its own separate check.
  app.use(observabilityRouter);

  app.use("/auth", authRouter);
  app.use("/api/ingest", ingestRouter);
  app.use("/api/agents", agentsRouter);
  app.use("/api/scan-jobs", scanJobsRouter);
  app.use("/api/hosts", hostsRouter);
  app.use("/api/screenshots", screenshotsRouter);
  app.use("/api/rdp-screenshots", rdpScreenshotsRouter);
  app.use("/api/schedules", schedulesRouter);
  app.use("/api/adhoc-scans", adhocScansRouter);
  app.use("/api/certificates", certificatesRouter);
  app.use("/api/vulnerabilities", vulnerabilitiesRouter);
  app.use("/api/users", usersRouter);
  app.use("/api/digest", digestRouter);
  app.use("/api/trends", trendsRouter);
  app.use("/api/webhooks", webhooksRouter);
  app.use("/api/audit", auditRouter);
  app.use("/api/excludes", excludesRouter);
  app.use("/api/api-tokens", apiTokensRouter);
  app.use("/api/saved-searches", savedSearchesRouter);
  app.use("/api/scan-profiles", scanProfilesRouter);
  app.use("/api/nuclei-profiles", nucleiProfilesRouter);
  app.use("/api/nuclei-findings", nucleiFindingsRouter);
  app.use("/api/finding-triage", findingTriageRouter);
  app.use("/api/settings", settingsRouter);
  // Mounted before integrationsRouter so the spec/UI stay outside its
  // tokenAuth chain - see docsRoutes.ts for why that's deliberate.
  app.use("/api/v1", apiDocsRouter);
  // External/SOAR-facing API - own auth chain (tokenAuth), not session auth.
  app.use("/api/v1", integrationsRouter);

  const frontendDist = path.join(__dirname, "..", "..", "frontend", "dist");
  if (fs.existsSync(frontendDist)) {
    app.use(express.static(frontendDist));
    // Express 5's router (path-to-regexp v6+) rejects a bare "*" outright
    // ("Missing parameter name") - confirmed by actually hitting this at
    // startup, not just reading the changelog. "/*splat" is the documented
    // replacement: a named wildcard that still matches any nested client-
    // side route (verified against real requests down to multiple path
    // segments deep, e.g. /some/deeply/nested/route).
    app.get("/*splat", (_req, res) => {
      res.sendFile(path.join(frontendDist, "index.html"));
    });
  }

  // Central error handling: prevents an error in a route from taking down
  // the entire process via an unhandled rejection.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    logger.error(
      { event: "http.unhandled_error", method: req.method, path: req.path, err: err instanceof Error ? err.message : String(err) },
      "Unhandled request error"
    );
    if (!res.headersSent) {
      res.status(500).json({ error: "internal server error" });
    }
  });

  return app;
}
