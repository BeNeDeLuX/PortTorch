// Whether a detected product version is still supported upstream.
//
// Derived on read, like windowsBuilds.ts, and for the same reason: support
// dates pass and releases appear, so keeping the table here means a lapsed
// date reaches every existing host on the next deploy rather than only the
// hosts scanned afterwards.
//
// Deliberately narrow. A product is only listed when its project publishes
// an end-of-support date per release branch, and only branches whose date
// is known with confidence. Left out on purpose:
//   - OpenSSH, Dropbear, nginx, Samba, Docker: no per-branch lifecycle to
//     point at, or one whose dates would be guesses.
//   - anything detected without a usable version ("9.6.0 or later",
//     "3.X - 4.X", or no version at all).
// A product that is not listed shows nothing, which is a statement about
// what is known - never an implied "supported".
//
// Everything here is the *upstream* project's support. A Linux distribution
// often keeps patching a branch long after upstream stopped (RHEL's PHP,
// Debian's Apache), so an end-of-life badge means "upstream no longer
// fixes this" - worth checking, not proof the host is unpatched. The UI
// says so wherever it shows one.

interface Product {
  // Matched against the detected product name, case-insensitively.
  match: RegExp;
  // How many leading version components identify a release branch for
  // this product: PHP 8.1 is a branch, PostgreSQL 13 is.
  branch: (parts: number[]) => string | null;
  // Branch -> the date upstream support ended (or ends).
  ends: Record<string, string>;
  // Every branch older than the oldest listed one has also ended, as of
  // this date - so "PHP 5.4" does not show as unknown.
  olderEnded?: { before: number[]; date: string };
}

const majorMinor = (p: number[]) => (p.length >= 2 ? `${p[0]}.${p[1]}` : null);
const major = (p: number[]) => (p.length >= 1 ? `${p[0]}` : null);

const PRODUCTS: Record<string, Product> = {
  PHP: {
    match: /^php$/i,
    branch: majorMinor,
    ends: {
      "5.6": "2018-12-31",
      "7.0": "2019-01-10",
      "7.1": "2019-12-01",
      "7.2": "2020-11-30",
      "7.3": "2021-12-06",
      "7.4": "2022-11-28",
      "8.0": "2023-11-26",
      "8.1": "2025-12-31",
      "8.2": "2026-12-31",
      "8.3": "2027-12-31",
      "8.4": "2028-12-31",
    },
    olderEnded: { before: [5, 6], date: "2018-12-31" },
  },
  Python: {
    match: /^python$/i,
    branch: majorMinor,
    ends: {
      "2.7": "2020-01-01",
      "3.5": "2020-09-30",
      "3.6": "2021-12-23",
      "3.7": "2023-06-27",
      "3.8": "2024-10-07",
      "3.9": "2025-10-31",
    },
    olderEnded: { before: [2, 7], date: "2020-01-01" },
  },
  "Node.js": {
    match: /^node\.?js$/i,
    branch: major,
    ends: {
      "12": "2022-04-30",
      "14": "2023-04-30",
      "16": "2023-09-11",
      "18": "2025-04-30",
      "20": "2026-04-30",
      "22": "2027-04-30",
      "24": "2028-04-30",
    },
    olderEnded: { before: [12], date: "2022-04-30" },
  },
  PostgreSQL: {
    match: /^postgresql( db)?$/i,
    // Major version since 10; before that the first two numbers.
    branch: (p) => (p[0] >= 10 ? major(p) : majorMinor(p)),
    ends: {
      "9.6": "2021-11-11",
      "10": "2022-11-10",
      "11": "2023-11-09",
      "12": "2024-11-21",
      "13": "2025-11-13",
      "14": "2026-11-12",
      "15": "2027-11-11",
      "16": "2028-11-09",
      "17": "2029-11-08",
    },
    olderEnded: { before: [9, 6], date: "2021-11-11" },
  },
  MySQL: {
    match: /^mysql$/i,
    branch: majorMinor,
    ends: { "5.6": "2021-02-05", "5.7": "2023-10-31", "8.0": "2026-04-30" },
    olderEnded: { before: [5, 6], date: "2021-02-05" },
  },
  MongoDB: {
    match: /^mongodb$/i,
    branch: majorMinor,
    ends: { "4.4": "2024-02-29", "5.0": "2024-10-31", "6.0": "2025-07-31" },
    olderEnded: { before: [4, 4], date: "2024-02-29" },
  },
  "Apache HTTP Server": {
    match: /^apache( httpd| http server)$/i,
    branch: majorMinor,
    ends: { "1.3": "2010-02-03", "2.0": "2013-07-10", "2.2": "2017-07-11" },
  },
  "Apache Tomcat": {
    match: /^apache tomcat$/i,
    // 8.0 and 8.5 are separate branches with separate ends; elsewhere the
    // major version is the branch.
    branch: (p) => (p[0] === 8 ? majorMinor(p) : major(p)),
    ends: { "7": "2021-03-31", "8.0": "2018-06-30", "8.5": "2024-03-31" },
    olderEnded: { before: [7], date: "2021-03-31" },
  },
  Jetty: {
    match: /^jetty$/i,
    branch: major,
    // End of community support.
    ends: { "9": "2022-06-01", "10": "2024-01-01", "11": "2024-01-01" },
    olderEnded: { before: [9], date: "2022-06-01" },
  },
  OpenSSL: {
    match: /^openssl$/i,
    branch: (p) => (p[0] >= 3 ? majorMinor(p) : p.length >= 3 ? `${p[0]}.${p[1]}.${p[2]}` : null),
    ends: { "1.0.2": "2019-12-31", "1.1.0": "2019-09-11", "1.1.1": "2023-09-11", "3.0": "2026-09-07", "3.1": "2025-03-14" },
    olderEnded: { before: [1, 0, 2], date: "2019-12-31" },
  },
  AngularJS: {
    match: /^angularjs$/i,
    // Every AngularJS release - the framework as a whole ended.
    branch: () => "1",
    ends: { "1": "2021-12-31" },
  },
  Bootstrap: {
    match: /^bootstrap$/i,
    branch: major,
    ends: { "3": "2019-07-24", "4": "2023-01-01" },
    olderEnded: { before: [3], date: "2019-07-24" },
  },
  Django: {
    match: /^django$/i,
    branch: majorMinor,
    ends: { "2.2": "2022-04-11", "3.2": "2024-04-01", "4.0": "2023-04-01", "4.1": "2023-12-01", "4.2": "2026-04-30", "5.0": "2025-04-02", "5.1": "2025-12-03" },
    olderEnded: { before: [2, 2], date: "2022-04-11" },
  },
};

// Warn this far ahead of a scheduled end: long enough to plan an upgrade.
const ENDING_SOON_DAYS = 180;

export type LifecycleStatus = "ended" | "ending";

export interface Lifecycle {
  status: LifecycleStatus;
  product: string;
  branch: string;
  date: string;
  label: string;
}

// The leading dotted number of a version string, or null when the string
// does not commit to one ("9.6.0 or later", "3.X - 4.X", "unknown").
export function parseVersion(version: string): number[] | null {
  const v = version.trim();
  if (/or later|or earlier|\bx\b| - /i.test(v)) return null;
  const m = /^v?(\d+(?:\.\d+)*)/i.exec(v);
  return m ? m[1].split(".").map(Number) : null;
}

function older(a: number[], b: number[]): boolean {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

// What to say about a product+version, or null when there is nothing
// worth flagging: an unlisted product, an unusable version, or a branch
// supported for longer than the warning window.
export function lifecycleOf(product: string, version: string | null, now: Date = new Date()): Lifecycle | null {
  if (!version) return null;
  const entry = Object.entries(PRODUCTS).find(([, p]) => p.match.test(product.trim()));
  if (!entry) return null;
  const [name, p] = entry;
  const parts = parseVersion(version);
  if (!parts) return null;
  const branch = p.branch(parts);
  if (!branch) return null;

  let date = p.ends[branch];
  if (!date && p.olderEnded && older(parts, p.olderEnded.before)) date = p.olderEnded.date;
  if (!date) return null;

  const days = (Date.parse(`${date}T00:00:00Z`) - now.getTime()) / 86_400_000;
  if (days > ENDING_SOON_DAYS) return null;
  const status: LifecycleStatus = days <= 0 ? "ended" : "ending";
  return {
    status,
    product: name,
    branch,
    date,
    label: status === "ended" ? `${name} ${branch}: upstream support ended ${date}` : `${name} ${branch}: upstream support ends ${date}`,
  };
}

export const LIFECYCLE_CAVEAT =
  "Upstream support only. A Linux distribution may still be patching this branch - check the host's own package before treating it as unpatched.";
