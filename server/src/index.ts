import https from "https";
import { config } from "./config";
import { pgPool } from "./db";
import { logger } from "./logger";
import { loadOrCreateSelfSignedCert } from "./tls/generateCert";
import { buildApp } from "./app";
import { startCertificateExpiryAlerts } from "./webhooks/expiryAlerts";
import { startSavedSearchAlerts } from "./savedSearches/checker";
import { startCveSync } from "./cve/sync";
import { startEpssSync } from "./cve/epssSync";
import { startKevSync } from "./cve/kevSync";
import { startScheduler } from "./scheduler";
import { startRetention } from "./retention";
import { startDailyDigestEmail } from "./digest/emailDigest";

// An error on an idle pool client would otherwise arrive as an
// uncaughtException on the process and take down the entire server.
pgPool.on("error", (err) => {
  logger.error({ event: "db.pool_error", err: err.message }, "Unexpected postgres pool error");
});

const app = buildApp();
const { key, cert } = loadOrCreateSelfSignedCert(config.certDir);

https.createServer({ key, cert }, app).listen(config.port, () => {
  logger.info({ event: "server.started", port: config.port }, `PortTorch webserver listening on https://0.0.0.0:${config.port}`);
});

startScheduler();
startCertificateExpiryAlerts();
startRetention();
startSavedSearchAlerts();
startCveSync();
startEpssSync();
startKevSync();
startDailyDigestEmail();
