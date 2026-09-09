import http from "http";
import https from "https";
import net from "net";
import { URL } from "url";
import { proxyForUrl, ProxyConfig } from "./proxy";
import { getAppSettings } from "../settings/appSettings";

export interface OutboundResult {
  ok: boolean;
  status?: number;
  error?: string;
  /** Response body, only collected when the caller asked for one. */
  body?: string;
}

/** Kept as the old name so existing callers read unchanged. */
export type OutboundPostResult = OutboundResult;

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
  // The proxy configuration to use. Omitted means "look it up" - see
  // resolveProxy below on why that is the default rather than an
  // env-only fallback.
  proxy?: ProxyConfig | null;
}

export interface OutboundGetOptions extends OutboundPostOptions {
  // A successful response body is only worth collecting when someone is
  // going to read it, and the API responses these fetch are large - the
  // KEV catalogue alone is over a megabyte.
  maxResponseBytes?: number;
}

/**
 * Every outbound request resolves its proxy the same way, and a caller
 * that forgets to pass one gets the configured value rather than the
 * environment. That default is deliberate: an env-only fallback would
 * mean a call site added later silently keeps using .env after an admin
 * has moved the proxy into Settings, which is precisely the split this
 * module exists to end. One extra settings read per outbound network
 * call is not measurable against the call itself.
 */
async function resolveProxy(options: { proxy?: ProxyConfig | null }): Promise<ProxyConfig | null> {
  if (options.proxy !== undefined) return options.proxy;
  try {
    return (await getAppSettings()).proxy;
  } catch {
    // A settings read that fails must not stop an outbound request that
    // might well work: fall through to the environment, which is what
    // proxyForUrl does with a null config.
    return null;
  }
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
  const proxy = proxyForUrl(targetUrl, await resolveProxy(options));
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
  payload: Buffer | null,
  maxErrorBytes: number,
  // When set, a successful body is collected up to this many bytes. Left
  // undefined for POST, whose callers only ever want to know whether it
  // landed - keeping a delivery's response would put an arbitrary target's
  // output in memory for nothing.
  maxResponseBytes?: number
): Promise<OutboundResult> {
  return new Promise<OutboundResult>((resolve) => {
    const req = transport.request(options, (res) => {
      const status = res.statusCode ?? 0;
      const ok = status >= 200 && status < 300;
      const budget = ok ? maxResponseBytes ?? maxErrorBytes : maxErrorBytes;
      const chunks: Buffer[] = [];
      let size = 0;
      // Read to the end even when the body is not wanted, so the socket
      // can be reused and the response is not left dangling.
      res.on("data", (c: Buffer) => {
        if (size < budget) {
          chunks.push(c);
          size += c.length;
        }
      });
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (ok) {
          resolve({ ok: true, status, ...(maxResponseBytes ? { body: text.slice(0, maxResponseBytes) } : {}) });
          return;
        }
        const snippet = text.slice(0, maxErrorBytes);
        resolve({ ok: false, status, error: `target responded ${status}${snippet ? `: ${snippet}` : ""}` });
      });
    });
    req.on("timeout", () => req.destroy(new Error("target did not respond in time")));
    req.on("error", (err) => resolve({ ok: false, error: err.message }));
    req.end(payload ?? undefined);
  });
}

/**
 * A GET over the same three paths outboundPost uses - direct, through a
 * proxy in absolute form, and over a CONNECT tunnel - returning the
 * response body.
 *
 * This exists so the NVD, EPSS, KEV, GitHub and Docker Hub syncs stop
 * using fetch. Two things follow from that, and both are the point rather
 * than side effects: the proxy becomes a live setting for them too
 * (undici captures the environment at startup and cannot be changed
 * afterwards), and they gain the uploaded CA bundle, which fetch cannot
 * take at all - so a proxy that terminates TLS with its own certificate,
 * the normal corporate arrangement, is now something an admin can fix
 * from the dashboard instead of an unfixable sync failure.
 */
export async function outboundGet(targetUrl: string, options: OutboundGetOptions = {}): Promise<OutboundResult> {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return { ok: false, error: "not a valid URL" };
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return { ok: false, error: "url must be http or https" };
  }

  const maxErrorBytes = options.maxErrorBytes ?? 300;
  const maxResponseBytes = options.maxResponseBytes ?? 32 * 1024 * 1024;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const proxy = proxyForUrl(targetUrl, await resolveProxy(options));
  const targetPort = Number(target.port || (target.protocol === "https:" ? 443 : 80));
  // gzip is deliberately not requested: fetch decompressed transparently,
  // and asking for it here would mean decompressing by hand for no gain
  // on an hourly job.
  const headers = { Accept: "application/json", ...options.headers };

  if (proxy && target.protocol === "http:") {
    return sendRequest(http, {
      hostname: proxy.hostname,
      port: Number(proxy.port || 80),
      path: targetUrl,
      method: "GET",
      headers: { Host: target.host, ...proxyAuthHeader(proxy), ...headers },
      timeout: timeoutMs,
    }, null, maxErrorBytes, maxResponseBytes);
  }

  if (proxy && target.protocol === "https:") {
    return new Promise<OutboundResult>((resolve) => {
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
        sendRequest(https, {
          socket,
          agent: false,
          servername: target.hostname,
          host: target.hostname,
          port: targetPort,
          path: `${target.pathname}${target.search}`,
          method: "GET",
          headers,
          rejectUnauthorized: options.verifyTls ?? true,
          ...(options.ca ? { ca: options.ca } : {}),
          timeout: timeoutMs,
        }, null, maxErrorBytes, maxResponseBytes)
          // Same leak the POST path documents: with `agent: false` and a
          // socket handed in, nothing else ever closes it.
          .finally(() => socket.destroy())
          .then(resolve);
      });
      connectReq.on("timeout", () => connectReq.destroy(new Error("proxy did not respond in time")));
      connectReq.on("error", (err) => resolve({ ok: false, error: `proxy connection failed: ${err.message}` }));
      connectReq.end();
    });
  }

  return sendRequest(target.protocol === "https:" ? https : http, {
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === "https:" ? 443 : 80),
    path: `${target.pathname}${target.search}`,
    method: "GET",
    headers,
    rejectUnauthorized: options.verifyTls ?? true,
    ...(options.ca ? { ca: options.ca } : {}),
    timeout: timeoutMs,
  }, null, maxErrorBytes, maxResponseBytes);
}
