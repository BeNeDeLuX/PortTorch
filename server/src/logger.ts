import pino from "pino";

/**
 * Structured NDJSON logging (one JSON line per event) on stdout. This lets
 * the log stream be forwarded unchanged, via any container log driver
 * (Docker json-file, journald, ...), by a log shipper (Filebeat, Fluent
 * Bit, Vector, ...) to a SIEM.
 *
 * IMPORTANT: never log passwords, API keys, or Authorization headers
 * through this logger - only IDs/names, never secrets.
 */
export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  timestamp: pino.stdTimeFunctions.isoTime,
  base: { service: "porttorch-webserver" },
});
