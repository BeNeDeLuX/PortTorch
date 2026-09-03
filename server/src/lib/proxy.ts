import { URL } from "url";

/**
 * Which proxy, if any, an outbound request to `targetUrl` should go
 * through, read from the conventional environment variables.
 *
 * This exists only for lib/outboundPost.ts, which talks to alert
 * channels and SIEM collectors over Node's http/https modules rather
 * than fetch (it needs a CA bundle and rejectUnauthorized, neither of
 * which fetch can take). Everything that does use fetch - the NVD, EPSS,
 * KEV and GitHub syncs - is covered by Node's own NODE_USE_ENV_PROXY,
 * set in the Dockerfile; the http/https modules have no equivalent, so
 * this is the missing half rather than a second mechanism.
 *
 * Deliberately reads the environment on every call rather than caching:
 * these are process-lifetime values in practice, and a cache would only
 * add a way for a restart-free config change to be silently ignored.
 */
export function proxyForUrl(targetUrl: string): URL | null {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return null;
  }

  if (matchesNoProxy(target.hostname, target.port || defaultPort(target.protocol))) return null;

  // Lowercase wins over uppercase where both are set, matching curl and
  // most language runtimes. HTTPS_PROXY is only consulted for https
  // targets, HTTP_PROXY only for http ones - a single proxy that serves
  // both is simply named in both variables, which is what the tooling
  // that sets them already does.
  const raw =
    target.protocol === "https:"
      ? process.env.https_proxy || process.env.HTTPS_PROXY
      : process.env.http_proxy || process.env.HTTP_PROXY;
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
export function matchesNoProxy(hostname: string, port: string): boolean {
  const raw = process.env.no_proxy || process.env.NO_PROXY;
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
