import https from "https";
import { config } from "./config";
import { pgPool } from "./db";
import { logger } from "./logger";
import { loadOrCreateSelfSignedCert } from "./tls/generateCert";
import { setActiveHttpsServer } from "./tls/activeServer";
import { buildApp } from "./app";
import { startCertificateExpiryAlerts } from "./webhooks/expiryAlerts";
import { startOperationalAlerts } from "./webhooks/operationalAlerts";
import { startWebhookRetryQueue } from "./webhooks/retryQueue";
import { startWebserverCertExpiryAlert } from "./settings/certExpiryAlert";
import { startSavedSearchAlerts } from "./savedSearches/checker";
import { startCveSync } from "./cve/sync";
import { startEpssSync } from "./cve/epssSync";
import { startKevSync } from "./cve/kevSync";
import { startScheduler } from "./scheduler";
import { startRetention } from "./retention";
import { startDailyDigestEmail } from "./digest/emailDigest";
import { startGithubSync } from "./scannerUpdate/githubSync";

// An error on an idle pool client would otherwise arrive as an
// uncaughtException on the process and take down the entire server.
pgPool.on("error", (err) => {
  logger.error({ event: "db.pool_error", err: err.message }, "Unexpected postgres pool error");
});

const app = buildApp();
const { key, cert } = loadOrCreateSelfSignedCert(config.certDir);

const httpsServer = https.createServer({ key, cert }, app);
// Registered before .listen() so it's set as soon as anyone could
// conceivably reach the settings route - setSecureContext (see
// settings/routes.ts) applies a newly-uploaded certificate to this same
// live listener immediately, no restart needed.
setActiveHttpsServer(httpsServer);
httpsServer.listen(config.port, () => {
  logger.info({ event: "server.started", port: config.port }, `PortTorch webserver listening on https://0.0.0.0:${config.port}`);
});

startScheduler();
startCertificateExpiryAlerts();
startWebserverCertExpiryAlert();
startOperationalAlerts();
startRetention();
startSavedSearchAlerts();
startCveSync();
startEpssSync();
startKevSync();
startDailyDigestEmail();
startGithubSync();
startWebhookRetryQueue();
