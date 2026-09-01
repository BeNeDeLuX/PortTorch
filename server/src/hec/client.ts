import http from "http";
import https from "https";
import { URL } from "url";
import type { HecSettings } from "../settings/appSettings";
import { serializeBatch, type HecEvent } from "./format";

// Splunk's own path, and the one every HEC-compatible collector accepts.
// The admin enters a base URL, so this is appended rather than being part
// of what they type - but a URL that already ends in /services/collector
// is left alone, since that is the form most vendor documentation shows.
export function collectorUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim().replace(/\/+$/, "");
  if (/\/services\/collector(\/event)?$/.test(trimmed)) return trimmed;
  return `${trimmed}/services/collector/event`;
}

export interface HecPostResult {
  ok: boolean;
  status?: number;
  error?: string;
}

// Node's https module rather than fetch, and deliberately: an internally
// hosted collector very often has a self-signed certificate, and
// rejectUnauthorized is not reachable through fetch (undici ignores an
// `agent` option, and its own Agent is not importable without adding
// undici as a dependency). Everywhere else in this codebase does use
// fetch - webhooks, the GitHub release sync - because none of those needs
// to talk to a box with a private CA.
export async function postToHec(settings: HecSettings, events: HecEvent[]): Promise<HecPostResult> {
  if (!settings.url || !settings.token) {
    return { ok: false, error: "no collector URL or token configured" };
  }
  if (events.length === 0) return { ok: true };

  let target: URL;
  try {
    target = new URL(collectorUrl(settings.url));
  } catch {
    return { ok: false, error: "collector URL is not a valid URL" };
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return { ok: false, error: "collector URL must be http or https" };
  }

  const body = Buffer.from(serializeBatch(events), "utf8");
  const transport = target.protocol === "https:" ? https : http;

  return new Promise<HecPostResult>((resolve) => {
    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method: "POST",
        headers: {
          // "Splunk <token>" is the scheme every HEC implementation expects.
          Authorization: `Splunk ${settings.token}`,
          "Content-Type": "application/json",
          "Content-Length": body.byteLength,
        },
        // Only meaningful for https; harmless on http.
        rejectUnauthorized: settings.verifyTls,
        // Bounded so a hung collector can't stall the forwarder - the tick
        // just fails, the cursor doesn't move, and the next tick retries.
        timeout: 20_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        // The body is read even on success so the socket can be reused
        // and the response isn't left dangling.
        res.on("data", (c: Buffer) => {
          if (chunks.length < 8) chunks.push(c);
        });
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            resolve({ ok: true, status });
            return;
          }
          const text = Buffer.concat(chunks).toString("utf8").slice(0, 300);
          resolve({ ok: false, status, error: `collector returned ${status}${text ? `: ${text}` : ""}` });
        });
      }
    );

    req.on("timeout", () => req.destroy(new Error("collector did not respond within 20s")));
    req.on("error", (err) => resolve({ ok: false, error: err.message }));
    req.end(body);
  });
}
