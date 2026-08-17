// Derives a host's auto-tags from its open ports at ingest time - a TS-
// side classification, deliberately not a shared import from the Go
// scanner (mirrors how scanProfiles/knownNseScripts.ts is its own
// independent copy of the Go NSE lists, used only for a different
// purpose here than execution). Each rule mirrors the service-name/port
// heuristic an equivalent Go classifier already uses where one exists
// (isHTTPPort, isSMBPort, isRDPPort) - service name first (nmap's own
// -sV detection), a well-known port number as fallback for a port nmap
// only identified generically.
interface TaggablePort {
  port: number;
  protocol: string;
  state: string;
  serviceName?: string | null;
}

interface ServiceTagRule {
  tag: string;
  serviceNameHints: string[];
  ports?: number[];
  protocol?: "tcp" | "udp";
}

const RULES: ServiceTagRule[] = [
  {
    tag: "WebServer",
    serviceNameHints: ["http", "ssl"],
    ports: [80, 443, 8000, 8006, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9000],
  },
  { tag: "FTP-Server", serviceNameHints: ["ftp"], ports: [21] },
  { tag: "SSH-Server", serviceNameHints: ["ssh"], ports: [22] },
  { tag: "Telnet", serviceNameHints: ["telnet"], ports: [23] },
  { tag: "DNS-Server", serviceNameHints: ["domain", "dns"], ports: [53] },
  { tag: "RDP", serviceNameHints: ["ms-wbt-server", "rdp"], ports: [3389] },
  { tag: "SMB", serviceNameHints: ["microsoft-ds", "netbios-ssn", "smb"], ports: [445, 139] },
  { tag: "Mail-Server", serviceNameHints: ["smtp", "pop3", "imap"], ports: [25, 110, 143, 465, 587, 993, 995] },
  { tag: "LDAP", serviceNameHints: ["ldap"], ports: [389, 636] },
  { tag: "VNC", serviceNameHints: ["vnc"], ports: [5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910] },
  { tag: "MySQL", serviceNameHints: ["mysql"], ports: [3306] },
  { tag: "PostgreSQL", serviceNameHints: ["postgres"], ports: [5432] },
  { tag: "MSSQL", serviceNameHints: ["ms-sql"], ports: [1433] },
  { tag: "MongoDB", serviceNameHints: ["mongodb", "mongod"], ports: [27017] },
  { tag: "Redis", serviceNameHints: ["redis"], ports: [6379] },
  { tag: "Docker-API", serviceNameHints: ["docker"], ports: [2375, 2376] },
  { tag: "SNMP", serviceNameHints: ["snmp"], ports: [161], protocol: "udp" },
  { tag: "IPMI", serviceNameHints: ["ipmi"], ports: [623], protocol: "udp" },
];

export function deriveServiceTags(ports: TaggablePort[]): string[] {
  const tags = new Set<string>();
  for (const p of ports) {
    if (p.state !== "open") continue;
    const name = (p.serviceName ?? "").toLowerCase();
    const protocol = p.protocol.toLowerCase();
    for (const rule of RULES) {
      if (tags.has(rule.tag)) continue;
      if (rule.protocol && rule.protocol !== protocol) continue;
      const nameMatch = rule.serviceNameHints.some((hint) => name.includes(hint));
      const portMatch = rule.ports?.includes(p.port) ?? false;
      if (nameMatch || portMatch) tags.add(rule.tag);
    }
  }
  return [...tags];
}
