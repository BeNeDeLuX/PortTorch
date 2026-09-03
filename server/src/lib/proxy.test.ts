import { afterEach, describe, expect, it } from "vitest";
import { matchesNoProxy, proxyForUrl } from "./proxy";

const PROXY_VARS = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"];

function clearProxyEnv() {
  for (const name of PROXY_VARS) delete process.env[name];
}

afterEach(clearProxyEnv);

describe("proxyForUrl", () => {
  it("returns nothing when no proxy is configured", () => {
    clearProxyEnv();
    expect(proxyForUrl("https://hooks.slack.com/services/x")).toBeNull();
  });

  it("picks the variable matching the target's scheme", () => {
    clearProxyEnv();
    process.env.HTTP_PROXY = "http://proxy.internal:3128";
    process.env.HTTPS_PROXY = "http://tls-proxy.internal:3129";
    expect(proxyForUrl("http://collector.internal:8088")?.port).toBe("3128");
    expect(proxyForUrl("https://hooks.slack.com/x")?.port).toBe("3129");
  });

  it("prefers the lowercase variable, as curl does", () => {
    clearProxyEnv();
    process.env.https_proxy = "http://lower.internal:3128";
    process.env.HTTPS_PROXY = "http://upper.internal:3129";
    expect(proxyForUrl("https://example.com")?.hostname).toBe("lower.internal");
  });

  it("treats a malformed proxy variable as no proxy rather than throwing mid-delivery", () => {
    clearProxyEnv();
    process.env.HTTPS_PROXY = "not a url";
    expect(proxyForUrl("https://example.com")).toBeNull();
    process.env.HTTPS_PROXY = "ftp://proxy.internal:21";
    expect(proxyForUrl("https://example.com")).toBeNull();
  });

  it("skips the proxy for a NO_PROXY match", () => {
    clearProxyEnv();
    process.env.HTTPS_PROXY = "http://proxy.internal:3128";
    process.env.NO_PROXY = "internal,localhost";
    expect(proxyForUrl("https://collector.internal/x")).toBeNull();
    expect(proxyForUrl("https://hooks.slack.com/x")).not.toBeNull();
  });
});

describe("matchesNoProxy", () => {
  it("matches a domain and its subdomains, on label boundaries", () => {
    clearProxyEnv();
    process.env.NO_PROXY = "internal";
    expect(matchesNoProxy("internal", "443")).toBe(true);
    expect(matchesNoProxy("logs.internal", "443")).toBe(true);
    // The case a plain suffix check gets wrong, and the reason this is
    // not endsWith on its own.
    expect(matchesNoProxy("notinternal", "443")).toBe(false);
  });

  it("accepts a leading dot, which is how most tools write it", () => {
    clearProxyEnv();
    process.env.NO_PROXY = ".example.com";
    expect(matchesNoProxy("api.example.com", "443")).toBe(true);
    expect(matchesNoProxy("example.com", "443")).toBe(true);
  });

  it("honours a port when the entry carries one", () => {
    clearProxyEnv();
    process.env.NO_PROXY = "collector.internal:8088";
    expect(matchesNoProxy("collector.internal", "8088")).toBe(true);
    expect(matchesNoProxy("collector.internal", "443")).toBe(false);
  });

  it("supports the wildcard", () => {
    clearProxyEnv();
    process.env.NO_PROXY = "*";
    expect(matchesNoProxy("anything.example.com", "443")).toBe(true);
  });

  it("is case-insensitive and ignores blank entries", () => {
    clearProxyEnv();
    process.env.no_proxy = " , INTERNAL , ";
    expect(matchesNoProxy("Logs.Internal", "443")).toBe(true);
  });
});
