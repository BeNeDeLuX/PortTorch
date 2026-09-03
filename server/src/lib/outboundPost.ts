import http from "http";
import https from "https";
import net from "net";
import { URL } from "url";
import { proxyForUrl } from "./proxy";

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
  const timeoutMs = options.timeoutMs ?? 20_000;
  const proxy = proxyForUrl(targetUrl);
  const targetPort = Number(target.port || (target.protocol === "https:" ? 443 : 80));

  // An http target through a proxy is just a request to the proxy with an
  // absolute-form request line - no tunnel, no extra round trip. https
  // needs a CONNECT tunnel first (below), because the whole point of the
  // TLS options this function exists for is that the proxy must not see
  // inside the connection.
  if (proxy && target.protocol === "http:") {
    return sendRequest(http, {
      hostname: proxy.hostname,
      port: Number(proxy.port || 80),
      path: targetUrl,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Host: target.host,
        ...proxyAuthHeader(proxy),
        ...options.headers,
        "Content-Length": payload.byteLength,
      },
      timeout: timeoutMs,
    }, payload, maxErrorBytes);
  }

  if (proxy && target.protocol === "https:") {
    return new Promise<OutboundPostResult>((resolve) => {
      const connectReq = http.request({
        host: proxy.hostname,
        port: Number(proxy.port || 80),
        method: "CONNECT",
        path: `${target.hostname}:${targetPort}`,
        headers: { Host: `${target.hostname}:${targetPort}`, ...proxyAuthHeader(proxy) },
        timeout: timeoutMs,
      });
      connectReq.on("connect", (res, socket: net.Socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          resolve({ ok: false, status: res.statusCode, error: `proxy refused CONNECT (${res.statusCode})` });
          return;
        }
        // The tunnel is now a plain socket to the target; TLS is
        // negotiated over it with the same verification and CA bundle a
        // direct connection would have used, so an uploaded internal CA
        // keeps working through a proxy.
        sendRequest(https, {
          socket,
          agent: false,
          servername: target.hostname,
          host: target.hostname,
          port: targetPort,
          path: `${target.pathname}${target.search}`,
          method: "POST",
          headers: { "Content-Type": "application/json", ...options.headers, "Content-Length": payload.byteLength },
          rejectUnauthorized: options.verifyTls ?? true,
          ...(options.ca ? { ca: options.ca } : {}),
          timeout: timeoutMs,
        }, payload, maxErrorBytes)
          .finally(() => {
            // The tunnel socket is ours, not an agent's: with
            // `agent: false` and a socket handed in, nothing else will
            // ever close it, and every proxied delivery would leak one
            // for the lifetime of the process. Found by a test teardown
            // that hung waiting for exactly these sockets to go idle.
            socket.destroy();
          })
          .then(resolve);
      });
      connectReq.on("timeout", () => connectReq.destroy(new Error("proxy did not respond in time")));
      connectReq.on("error", (err) => resolve({ ok: false, error: `proxy connection failed: ${err.message}` }));
      connectReq.end();
    });
  }

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

// Credentials embedded in the proxy URL (http://user:pass@proxy:3128),
// which is how they are conventionally supplied. Nothing logs this
// header - it is built here and handed straight to the request.
function proxyAuthHeader(proxy: URL): Record<string, string> {
  if (!proxy.username) return {};
  const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
  return { "Proxy-Authorization": `Basic ${Buffer.from(credentials).toString("base64")}` };
}

// The response half, shared by the three ways a request can be made
// (direct, through a proxy in absolute form, and over a CONNECT tunnel)
// so a proxied delivery reports success and failure exactly as a direct
// one does.
function sendRequest(
  transport: typeof http | typeof https,
  options: http.RequestOptions & Record<string, unknown>,
  payload: Buffer,
  maxErrorBytes: number
): Promise<OutboundPostResult> {
  return new Promise<OutboundPostResult>((resolve) => {
    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
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
    });
    req.on("timeout", () => req.destroy(new Error("target did not respond in time")));
    req.on("error", (err) => resolve({ ok: false, error: err.message }));
    req.end(payload);
  });
}
