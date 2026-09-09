import { URL } from "url";

/** The subset of app_settings.proxy this module needs. */
export interface ProxyConfig {
  httpUrl: string | null;
  httpsUrl: string | null;
  noProxy: string | null;
}

/**
 * Which proxy, if any, an outbound request to `targetUrl` should go
 * through - taken from the Settings page when configured there, and from
 * the conventional environment variables otherwise.
 *
 * This backs every outbound request the webserver makes - alert
 * channels, the SIEM collector, and (since the syncs moved onto
 * lib/outboundGet) the NVD, EPSS, KEV, GitHub and Docker Hub calls.
 *
 * It used to cover only the http/https-module half, with fetch relying on
 * Node's own NODE_USE_ENV_PROXY instead. That split is exactly why the
 * proxy could not become a dashboard setting: undici captures the
 * environment at process start and never re-reads it (measured, not
 * assumed - a variable set at runtime has no effect at all), so a
 * database-backed value would have applied to the alert channels
 * immediately and to the syncs only after a restart. One transport for
 * everything is what makes a single setting honest.
 *
 * Takes the configured values as a parameter rather than reading them
 * itself, the same shape lib/staleness.ts uses for its threshold: the
 * caller fetches getAppSettings() once and passes it down, so there is no
 * hidden cache to go stale in its own right.
 */
export function proxyForUrl(targetUrl: string, config?: ProxyConfig | null): URL | null {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return null;
  }

  if (matchesNoProxy(target.hostname, target.port || defaultPort(target.protocol), config?.noProxy)) return null;

  // Lowercase wins over uppercase where both are set, matching curl and
  // most language runtimes. HTTPS_PROXY is only consulted for https
  // targets, HTTP_PROXY only for http ones - a single proxy that serves
  // both is simply named in both variables, which is what the tooling
  // that sets them already does.
  //
  // A value configured on the Settings page wins; the environment is the
  // fallback, not a second source that also applies. That ordering is
  // what lets a deployment configured through .env keep working with
  // nothing to do, while an admin who fills the field in takes over from
  // that moment - without the two ever being blended.
  const configured = target.protocol === "https:" ? config?.httpsUrl : config?.httpUrl;
  const raw =
    (configured ?? "").trim() ||
    (target.protocol === "https:"
      ? process.env.https_proxy || process.env.HTTPS_PROXY
      : process.env.http_proxy || process.env.HTTP_PROXY);
  if (!raw) return null;

  try {
    const proxy = new URL(raw);
    if (proxy.protocol !== "http:" && proxy.protocol !== "https:") return null;
    return proxy;
  } catch {
    // A malformed proxy variable means no proxy rather than a thrown
    // error mid-delivery: the alert still has a chance of reaching a
    // target that happens to be reachable directly, and the failure is
    // reported the same way any other unreachable target is.
    return null;
  }
}

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}

/**
 * NO_PROXY matching, in the form the ecosystem actually agreed on rather
 * than any single specification: "*" disables proxying entirely, an
 * entry may carry a port to narrow it to that port, and a leading dot
 * (or a bare domain) matches subdomains as well as the domain itself.
 *
 * The subdomain rule is the one worth stating: "internal" matches
 * "logs.internal" but must NOT match "notinternal", so the comparison is
 * on label boundaries, not a plain suffix.
 */
export function matchesNoProxy(hostname: string, port: string, configured?: string | null): boolean {
  const raw = (configured ?? "").trim() || process.env.no_proxy || process.env.NO_PROXY;
  if (!raw) return false;

  const host = hostname.toLowerCase();
  for (const entry of raw.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean)) {
    if (entry === "*") return true;

    let pattern = entry;
    let entryPort: string | null = null;
    // An IPv6 literal is bracketed here exactly as it is in a URL, so the
    // port split has to be bracket-aware for the same reason the
    // ip_port excludes are (see the root CLAUDE.md).
    const lastColon = pattern.lastIndexOf(":");
    if (lastColon > pattern.lastIndexOf("]") && lastColon !== -1) {
      entryPort = pattern.slice(lastColon + 1);
      pattern = pattern.slice(0, lastColon);
    }
    if (entryPort && entryPort !== port) continue;

    pattern = pattern.replace(/^\./, "");
    if (host === pattern) return true;
    if (host.endsWith("." + pattern)) return true;
  }
  return false;
}
