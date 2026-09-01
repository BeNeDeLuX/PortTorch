import http from "http";
import https from "https";
import { URL } from "url";

export interface OutboundPostResult {
  ok: boolean;
  status?: number;
  error?: string;
}

export interface OutboundPostOptions {
  headers?: Record<string, string>;
  // Verify the server's certificate chain. Only meaningful for https.
  verifyTls?: boolean;
  // Extra trust anchors plus the public roots - see
  // settings/caCertificates.ts on why both.
  ca?: string[];
  timeoutMs?: number;
  // How much of an error response body to keep. Enough to identify the
  // problem, not enough to put a target's whole error page in a log line.
  maxErrorBytes?: number;
}

// A POST to a server the operator runs, over Node's http/https rather
// than fetch.
//
// fetch is what the rest of this codebase uses for outbound calls, and
// stays right for public endpoints - but it can take neither a CA bundle
// nor rejectUnauthorized (undici ignores an `agent` option and its own
// Agent isn't importable without taking on undici as a dependency). Both
// integrations that talk to internally hosted servers - the HEC collector
// and now webhook targets - need exactly those two things, so they share
// this instead of each hand-rolling it.
export async function outboundPost(
  targetUrl: string,
  body: string,
  options: OutboundPostOptions = {}
): Promise<OutboundPostResult> {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return { ok: false, error: "not a valid URL" };
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return { ok: false, error: "url must be http or https" };
  }

  const payload = Buffer.from(body, "utf8");
  const transport = target.protocol === "https:" ? https : http;
  const maxErrorBytes = options.maxErrorBytes ?? 300;

  return new Promise<OutboundPostResult>((resolve) => {
    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method: "POST",
        headers: { "Content-Type": "application/json", ...options.headers, "Content-Length": payload.byteLength },
        rejectUnauthorized: options.verifyTls ?? true,
        ...(options.ca ? { ca: options.ca } : {}),
        timeout: options.timeoutMs ?? 20_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        // Read even on success, so the socket can be reused and the
        // response isn't left dangling.
        res.on("data", (c: Buffer) => {
          if (size < maxErrorBytes) {
            chunks.push(c);
            size += c.length;
          }
        });
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            resolve({ ok: true, status });
            return;
          }
          const text = Buffer.concat(chunks).toString("utf8").slice(0, maxErrorBytes);
          resolve({ ok: false, status, error: `target responded ${status}${text ? `: ${text}` : ""}` });
        });
      }
    );

    req.on("timeout", () => req.destroy(new Error("target did not respond in time")));
    req.on("error", (err) => resolve({ ok: false, error: err.message }));
    req.end(payload);
  });
}
