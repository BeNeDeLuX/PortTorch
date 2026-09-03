import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import http from "http";
import https from "https";
import net from "net";
import { AddressInfo } from "net";
import forge from "node-forge";
import { outboundPost } from "../../src/lib/outboundPost";

// Real servers on loopback rather than a mocked http module: what is
// under test is whether a request actually reaches a proxy in the shape
// a proxy expects (absolute form for http, CONNECT for https), which a
// mock would only ever confirm about itself.
const PROXY_VARS = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"];

function clearProxyEnv() {
  for (const name of PROXY_VARS) delete process.env[name];
}

function selfSignedCert(): { cert: string; key: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: "commonName", value: "localhost" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert: forge.pki.certificateToPem(cert), key: forge.pki.privateKeyToPem(keys.privateKey) };
}

describe("outbound POST through a proxy", () => {
  let origin: http.Server;
  let tlsOrigin: https.Server;
  let proxy: http.Server;
  let originPort = 0;
  let tlsOriginPort = 0;
  let proxyPort = 0;

  // Every socket any of the three servers accepts or opens upstream, so
  // teardown can end them itself: close() waits for sockets to go idle,
  // and a proxy that has piped a tunnel holds two that never will.
  const sockets = new Set<net.Socket>();
  const originHits: string[] = [];
  const proxyHttpRequests: string[] = [];
  const proxyConnects: string[] = [];

  beforeAll(async () => {
    origin = http.createServer((req, res) => {
      originHits.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
    const { cert, key } = selfSignedCert();
    tlsOrigin = https.createServer({ cert, key }, (req, res) => {
      originHits.push(`TLS ${req.method} ${req.url}`);
      res.writeHead(200);
      res.end("{}");
    });

    proxy = http.createServer((req, res) => {
      // A proxied plain-http request arrives in absolute form
      // ("POST http://host:port/path"), which is exactly what
      // distinguishes it from a direct one.
      proxyHttpRequests.push(req.url ?? "");
      const target = new URL(req.url ?? "");
      const upstream = http.request(
        { hostname: target.hostname, port: target.port, path: target.pathname, method: req.method, headers: req.headers },
        (up) => {
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
        }
      );
      upstream.on("error", () => {
        res.writeHead(502);
        res.end();
      });
      req.pipe(upstream);
    });
    proxy.on("connect", (req, clientSocket, head) => {
      proxyConnects.push(req.url ?? "");
      const [host, port] = (req.url ?? "").split(":");
      const upstream = net.connect(Number(port), host, () => {
        sockets.add(upstream);
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head?.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on("error", () => clientSocket.end());
    });

    for (const server of [origin, tlsOrigin, proxy]) {
      server.on("connection", (socket: net.Socket) => sockets.add(socket));
      server.on("secureConnection", (socket: net.Socket) => sockets.add(socket));
    }
    await Promise.all(
      [origin, tlsOrigin, proxy].map((s) => new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve)))
    );
    originPort = (origin.address() as AddressInfo).port;
    tlsOriginPort = (tlsOrigin.address() as AddressInfo).port;
    proxyPort = (proxy.address() as AddressInfo).port;
  });

  afterEach(() => {
    clearProxyEnv();
    originHits.length = 0;
    proxyHttpRequests.length = 0;
    proxyConnects.length = 0;
  });

  afterAll(async () => {
    // closeAllConnections first: close() alone waits for existing sockets
    // to go idle, and the CONNECT tunnel above leaves one open on both
    // the proxy and the TLS origin - so the hook simply timed out.
    for (const socket of sockets) socket.destroy();
    await Promise.all(
      [origin, tlsOrigin, proxy].map((s) => {
        s.closeAllConnections();
        return new Promise<void>((resolve) => s.close(() => resolve()));
      })
    );
  });

  it("goes direct when no proxy is configured", async () => {
    const res = await outboundPost(`http://127.0.0.1:${originPort}/direct`, "{}");
    expect(res.ok).toBe(true);
    expect(originHits).toEqual(["POST /direct"]);
    expect(proxyHttpRequests).toHaveLength(0);
  });

  it("sends a plain-http target through the proxy in absolute form", async () => {
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    const res = await outboundPost(`http://127.0.0.1:${originPort}/collector`, JSON.stringify({ a: 1 }));
    expect(res.ok).toBe(true);
    expect(proxyHttpRequests).toEqual([`http://127.0.0.1:${originPort}/collector`]);
    expect(originHits).toEqual(["POST /collector"]);
  });

  it("tunnels an https target with CONNECT, keeping TLS options in force", async () => {
    process.env.HTTPS_PROXY = `http://127.0.0.1:${proxyPort}`;

    // Verification still applies through the tunnel: the origin's
    // certificate is self-signed and not trusted here, so this must fail
    // rather than quietly succeed because a proxy was involved.
    const verified = await outboundPost(`https://localhost:${tlsOriginPort}/hec`, "{}");
    expect(verified.ok).toBe(false);
    expect(proxyConnects).toEqual([`localhost:${tlsOriginPort}`]);

    // And with verification off, the same tunnel delivers.
    const unverified = await outboundPost(`https://localhost:${tlsOriginPort}/hec`, "{}", { verifyTls: false });
    expect(unverified.ok).toBe(true);
    expect(originHits).toContain("TLS POST /hec");
  });

  it("skips the proxy for a NO_PROXY match", async () => {
    process.env.HTTP_PROXY = `http://127.0.0.1:${proxyPort}`;
    process.env.NO_PROXY = "127.0.0.1";
    const res = await outboundPost(`http://127.0.0.1:${originPort}/internal`, "{}");
    expect(res.ok).toBe(true);
    expect(proxyHttpRequests).toHaveLength(0);
    expect(originHits).toEqual(["POST /internal"]);
  });

  it("reports a refused proxy as a failed delivery rather than throwing", async () => {
    // Port 1 on loopback: nothing listens there, so the proxy connection
    // itself fails - the case an operator hits with a typo'd variable.
    process.env.HTTP_PROXY = "http://127.0.0.1:1";
    const res = await outboundPost(`http://127.0.0.1:${originPort}/x`, "{}");
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/proxy|ECONNREFUSED/i);
  });
});
