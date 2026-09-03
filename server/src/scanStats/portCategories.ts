// Functional grouping of a discovered port, for the Scan Stats page's
// "Port types" chart.
//
// This is deliberately a small hand-maintained table of well-known ports
// rather than a lookup against nmap's own service_name: the point of that
// chart is a handful of readable slices ("Web", "Databases", "Remote
// access"), and service names are both far too granular for that (http,
// http-alt, http-proxy, ssl/http, ... are all "Web") and frequently null
// on a port nmap couldn't fingerprint. The Services chart beside it shows
// the raw service names for exactly that reason - the two answer different
// questions and neither replaces the other.
//
// Protocol is part of the key because a few numbers genuinely mean
// different things per protocol - 514/tcp is rsh (remote access) while
// 514/udp is syslog (infrastructure), and 69/udp is TFTP while 69/tcp is
// nothing in particular.
export type PortCategory =
  | "Web"
  | "Remote access"
  | "Databases"
  | "File sharing"
  | "Mail"
  | "Directory / auth"
  | "Network infrastructure"
  | "Industrial / OT"
  | "Other";

// The order slices are rendered in, so the chart's colors stay stable for
// a given category regardless of which categories a particular fleet
// happens to have. "Other" stays last (and gets the muted slot) since it
// is a residual, not a finding.
export const PORT_CATEGORY_ORDER: PortCategory[] = [
  "Web",
  "Remote access",
  "Databases",
  "File sharing",
  "Mail",
  "Directory / auth",
  "Network infrastructure",
  "Industrial / OT",
  "Other",
];

const TCP_ONLY: Record<number, PortCategory> = {
  514: "Remote access", // rsh - 514/udp is syslog, handled below
  69: "Other", // tftp is udp; a tcp/69 is not tftp
};

const UDP_ONLY: Record<number, PortCategory> = {
  514: "Network infrastructure", // syslog
  69: "File sharing", // tftp
};

const BY_PORT: Record<number, PortCategory> = {
  // Web
  80: "Web", 81: "Web", 443: "Web", 591: "Web", 3000: "Web", 4443: "Web",
  4567: "Web", 5000: "Web", 7001: "Web", 8000: "Web", 8008: "Web", 8009: "Web",
  8080: "Web", 8081: "Web", 8088: "Web", 8090: "Web", 8180: "Web", 8181: "Web",
  8443: "Web", 8834: "Web", 8888: "Web", 9090: "Web", 9443: "Web", 10000: "Web",

  // Remote access
  22: "Remote access", 23: "Remote access", 512: "Remote access", 513: "Remote access",
  3389: "Remote access", 5800: "Remote access", 5900: "Remote access", 5901: "Remote access",
  5902: "Remote access", 5903: "Remote access", 5985: "Remote access", 5986: "Remote access",
  6000: "Remote access", 6001: "Remote access",

  // Databases
  1433: "Databases", 1434: "Databases", 1521: "Databases", 3050: "Databases",
  3306: "Databases", 5432: "Databases", 5984: "Databases", 6379: "Databases",
  7199: "Databases", 8086: "Databases", 9042: "Databases", 9160: "Databases",
  9200: "Databases", 9300: "Databases", 11211: "Databases", 27017: "Databases",
  27018: "Databases", 27019: "Databases", 28017: "Databases", 50000: "Databases",

  // File sharing
  20: "File sharing", 21: "File sharing", 115: "File sharing", 139: "File sharing",
  445: "File sharing", 548: "File sharing", 873: "File sharing", 2049: "File sharing",
  3260: "File sharing",

  // Mail
  25: "Mail", 110: "Mail", 143: "Mail", 465: "Mail", 587: "Mail", 993: "Mail",
  995: "Mail", 2525: "Mail",

  // Directory / auth
  88: "Directory / auth", 389: "Directory / auth", 464: "Directory / auth",
  636: "Directory / auth", 749: "Directory / auth", 1812: "Directory / auth",
  1813: "Directory / auth", 3268: "Directory / auth", 3269: "Directory / auth",

  // Network infrastructure
  53: "Network infrastructure", 67: "Network infrastructure", 68: "Network infrastructure",
  111: "Network infrastructure", 123: "Network infrastructure", 135: "Network infrastructure",
  137: "Network infrastructure", 138: "Network infrastructure", 161: "Network infrastructure",
  162: "Network infrastructure", 179: "Network infrastructure", 500: "Network infrastructure",
  623: "Network infrastructure", 1194: "Network infrastructure", 1701: "Network infrastructure",
  1723: "Network infrastructure", 1900: "Network infrastructure", 4500: "Network infrastructure",
  5353: "Network infrastructure", 51820: "Network infrastructure",

  // Industrial / OT
  102: "Industrial / OT", 502: "Industrial / OT", 1911: "Industrial / OT",
  2404: "Industrial / OT", 4840: "Industrial / OT", 20000: "Industrial / OT",
  44818: "Industrial / OT", 47808: "Industrial / OT",
};

export function categorisePort(port: number, protocol: string): PortCategory {
  const proto = protocol === "udp" ? "udp" : "tcp";
  const perProtocol = proto === "udp" ? UDP_ONLY[port] : TCP_ONLY[port];
  if (perProtocol) return perProtocol;
  return BY_PORT[port] ?? "Other";
}
