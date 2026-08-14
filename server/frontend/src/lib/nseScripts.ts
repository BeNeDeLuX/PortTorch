// A third, frontend-only copy of the scanner's NSE script lists (see
// server/src/scanProfiles/knownNseScripts.ts and
// scanner/internal/pipeline/nse_default_scripts.go/nse_safe_scripts.go
// for the other two, and the "why three copies" reasoning there) - used
// ONLY to render the Scan Profiles admin page's checkbox options.
// Creating a custom profile is still validated server-side against the
// backend's own KNOWN_NSE_SCRIPTS, so a stale/out-of-sync frontend copy
// can never actually let an unrecognized script name through - it would
// just render a checkbox for a name the backend would then reject.
// Regenerate all three together.

export const DEFAULT_NSE_SCRIPTS: string[] = [
  "banner", "ssh-hostkey", "ftp-anon", "smb-enum-shares",
  "smb-os-discovery", "nbstat", "smb-protocols", "smb-security-mode", "smb2-security-mode",
  "nfs-showmount", "rsync-list-modules", "ldap-rootdse",
  "mongodb-info", "mongodb-databases", "redis-info", "mysql-info", "memcached-info", "oracle-tns-version",
  "docker-version", "couchdb-databases", "cassandra-info", "smtp-open-relay",
  "http-methods", "http-auth", "http-git",
  "rdp-ntlm-info", "rdp-enum-encryption", "ssh2-enum-algos", "sshv1",
  "rpcinfo", "msrpc-enum",
];

export const ALL_SAFE_NSE_SCRIPTS: string[] = [
  "acarsd-info", "address-info", "afp-ls", "afp-serverinfo", "afp-showmount", "ajp-auth", "ajp-headers",
  "ajp-methods", "ajp-request", "allseeingeye-info", "amqp-info", "asn-query", "auth-owners", "auth-spoof",
  "backorifice-info", "banner", "bitcoin-getaddr", "bitcoin-info", "bitcoinrpc-info", "bittorrent-discovery",
  "bjnp-discover", "broadcast-ataoe-discover", "broadcast-bjnp-discover", "broadcast-db2-discover",
  "broadcast-dhcp-discover", "broadcast-dhcp6-discover", "broadcast-dns-service-discovery",
  "broadcast-dropbox-listener", "broadcast-eigrp-discovery", "broadcast-hid-discoveryd",
  "broadcast-igmp-discovery", "broadcast-jenkins-discover", "broadcast-listener", "broadcast-ms-sql-discover",
  "broadcast-netbios-master-browser", "broadcast-networker-discover", "broadcast-novell-locate",
  "broadcast-ospf2-discover", "broadcast-pc-anywhere", "broadcast-pc-duo", "broadcast-pim-discovery",
  "broadcast-ping", "broadcast-pppoe-discover", "broadcast-rip-discover", "broadcast-ripng-discover",
  "broadcast-sonicwall-discover", "broadcast-sybase-asa-discover", "broadcast-tellstick-discover",
  "broadcast-upnp-info", "broadcast-versant-locate", "broadcast-wake-on-lan", "broadcast-wpad-discover",
  "broadcast-wsdd-discover", "broadcast-xdmcp-discover", "cassandra-info", "cics-info", "citrix-enum-apps",
  "citrix-enum-apps-xml", "citrix-enum-servers", "citrix-enum-servers-xml", "clock-skew", "coap-resources",
  "couchdb-databases", "couchdb-stats", "creds-summary", "cups-info", "cups-queue-info", "daap-get-library",
  "daytime", "db2-das-info", "dhcp-discover", "dicom-ping", "dict-info", "dns-blacklist", "dns-check-zone",
  "dns-client-subnet-scan", "dns-nsid", "dns-recursion", "dns-service-discovery", "dns-srv-enum",
  "dns-zeustracker", "docker-version", "drda-info", "duplicates", "eap-info", "epmd-info", "eppc-enum-processes",
  "fcrdns", "finger", "firewalk", "flume-master-info", "freelancer-info", "ftp-anon", "ftp-bounce", "ftp-syst",
  "ganglia-info", "giop-info", "gkrellm-info", "gopher-ls", "gpsd-info", "hadoop-datanode-info",
  "hadoop-jobtracker-info", "hadoop-namenode-info", "hadoop-secondary-namenode-info", "hadoop-tasktracker-info",
  "hbase-master-info", "hbase-region-info", "hddtemp-info", "hnap-info", "hostmap-robtex", "http-affiliate-id",
  "http-apache-negotiation", "http-apache-server-status", "http-auth", "http-auth-finder", "http-backup-finder",
  "http-bigip-cookie", "http-cakephp-version", "http-cisco-anyconnect", "http-comments-displayer",
  "http-cookie-flags", "http-cors", "http-cross-domain-policy", "http-date", "http-favicon", "http-fetch",
  "http-frontpage-login", "http-generator", "http-git", "http-gitweb-projects-enum", "http-google-malware",
  "http-grep", "http-headers", "http-hp-ilo-info", "http-icloud-findmyiphone", "http-icloud-sendmsg",
  "http-internal-ip-disclosure", "http-jsonp-detection", "http-ls", "http-malware-host", "http-mcmp",
  "http-methods", "http-mobileversion-checker", "http-ntlm-info", "http-open-proxy", "http-php-version",
  "http-qnap-nas-info", "http-referer-checker", "http-robots.txt", "http-robtex-reverse-ip",
  "http-robtex-shared-ns", "http-sap-netweaver-leak", "http-security-headers", "http-slowloris-check",
  "http-svn-enum", "http-svn-info", "http-title", "http-trace", "http-traceroute", "http-trane-info",
  "http-useragent-tester", "http-virustotal", "http-vlcstreamer-ls", "http-vmware-path-vuln",
  "http-vuln-cve2010-0738", "http-vuln-cve2011-3192", "http-vuln-cve2014-2126", "http-vuln-cve2014-2127",
  "http-vuln-cve2014-2128", "http-vuln-cve2014-2129", "http-vuln-cve2015-1635", "http-vuln-cve2017-1001000",
  "http-webdav-scan", "http-xssed", "icap-info", "ike-version", "imap-capabilities", "imap-ntlm-info",
  "ip-forwarding", "ip-geolocation-geoplugin", "ip-geolocation-ipinfodb", "ip-geolocation-map-bing",
  "ip-geolocation-map-google", "ip-geolocation-map-kml", "ip-geolocation-maxmind", "ip-https-discover", "ipidseq",
  "ipmi-cipher-zero", "ipmi-version", "ipv6-node-info", "irc-botnet-channels", "irc-info", "iscsi-info",
  "isns-info", "jdwp-info", "knx-gateway-discover", "knx-gateway-info", "ldap-novell-getpass", "ldap-rootdse",
  "ldap-search", "lexmark-config", "llmnr-resolve", "lltd-discovery", "maxdb-info", "mcafee-epo-agent",
  "membase-http-info", "memcached-info", "mongodb-databases", "mongodb-info", "mqtt-subscribe", "mrinfo",
  "ms-sql-config", "ms-sql-dac", "ms-sql-dump-hashes", "ms-sql-hasdbaccess", "ms-sql-info", "ms-sql-ntlm-info",
  "ms-sql-query", "ms-sql-tables", "msrpc-enum", "mtrace", "multicast-profinet-discovery", "mysql-audit",
  "mysql-dump-hashes", "mysql-info", "mysql-query", "nat-pmp-info", "nat-pmp-mapport", "nbns-interfaces", "nbstat",
  "ncp-enum-users", "ncp-serverinfo", "ndmp-fs-info", "netbus-auth-bypass", "netbus-info", "nfs-ls",
  "nfs-showmount", "nfs-statfs", "nntp-ntlm-info", "ntp-info", "omp2-enum-targets", "openflow-info",
  "openlookup-info", "openwebnet-discovery", "oracle-tns-version", "p2p-conficker", "path-mtu",
  "pop3-capabilities", "pop3-ntlm-info", "port-states", "qscan", "quake1-info", "quake3-info",
  "quake3-master-getservers", "rdp-enum-encryption", "rdp-ntlm-info", "realvnc-auth-bypass", "redis-info",
  "resolveall", "reverse-index", "rfc868-time", "riak-http-info", "rmi-dumpregistry", "rpcap-info", "rpcinfo",
  "rsa-vuln-roca", "rsync-list-modules", "rtsp-methods", "rusers", "servicetags", "shodan-api", "sip-methods",
  "smb-double-pulsar-backdoor", "smb-enum-shares", "smb-ls", "smb-mbenum", "smb-os-discovery", "smb-protocols",
  "smb-security-mode", "smb-vuln-ms17-010", "smb2-capabilities", "smb2-security-mode", "smb2-time",
  "smb2-vuln-uptime", "smtp-commands", "smtp-ntlm-info", "smtp-open-relay", "smtp-strangeport", "snmp-hh3c-logins",
  "snmp-info", "snmp-interfaces", "snmp-netstat", "snmp-processes", "snmp-sysdescr", "snmp-win32-services",
  "snmp-win32-shares", "snmp-win32-software", "snmp-win32-users", "socks-auth-info", "socks-open-proxy",
  "ssh-hostkey", "ssh2-enum-algos", "sshv1", "ssl-ccs-injection", "ssl-cert", "ssl-cert-intaddr", "ssl-date",
  "ssl-dh-params", "ssl-heartbleed", "ssl-known-key", "ssl-poodle", "sslv2", "sstp-discover", "stun-info",
  "targets-asn", "targets-sniffer", "targets-traceroute", "targets-xml", "telnet-encryption", "telnet-ntlm-info",
  "tftp-version", "tls-alpn", "tls-nextprotoneg", "tls-ticketbleed", "tn3270-screen", "tor-consensus-checker",
  "traceroute-geolocation", "ubiquiti-discovery", "unittest", "unusual-port", "upnp-info", "uptime-agent-info",
  "url-snarf", "ventrilo-info", "versant-info", "vmware-version", "vnc-info", "voldemort-info", "vulners",
  "vuze-dht-info", "wdb-version", "weblogic-t3-info", "whois-domain", "whois-ip", "wsdd-discover", "x11-access",
  "xdmcp-discover", "xmlrpc-methods", "xmpp-info",
];

// Additional Safe Modules = ALL_SAFE_NSE_SCRIPTS minus whatever's already
// in Default - the Scan Profiles page's "Additional Safe Modules"
// checkbox section shows only these, since Default's own 31 already have
// their own section.
export const ADDITIONAL_SAFE_NSE_SCRIPTS: string[] = ALL_SAFE_NSE_SCRIPTS.filter(
  (s) => !DEFAULT_NSE_SCRIPTS.includes(s)
);

// Purely a UI-side grouping for the Scan Profiles page's "Additional
// Safe Modules" checkbox list - 313 flat checkboxes in one long list has
// no way to select a whole family of related scripts at once, or even
// visually scan for one. Rules are prefix/name-based against nmap's own
// script-name conventions (there's no category metadata anywhere else to
// derive this from - nmap's own script.db only tags safe/intrusive/etc,
// not a finer protocol taxonomy), evaluated in order - each script lands
// in the first matching group. Deliberately a function over the flat
// list, not a hand-maintained per-script map: a future script added to
// ALL_SAFE_NSE_SCRIPTS automatically finds a home (falling back to
// "Other") without needing a second manual edit here. ~48 of 313 land in
// "Other" - a genuinely heterogeneous long tail of one-off protocol
// scripts that don't share a clear family, not a sign the rules are
// incomplete.
const CATEGORY_RULES: { name: string; match: (s: string) => boolean }[] = [
  { name: "HTTP / Web", match: (s) => s.startsWith("http-") },
  {
    name: "Broadcast / Network Discovery",
    match: (s) =>
      s.startsWith("broadcast-") ||
      ["dhcp-discover", "lltd-discovery", "llmnr-resolve", "wsdd-discover", "upnp-info", "xdmcp-discover",
        "targets-asn", "targets-sniffer", "targets-traceroute", "targets-xml", "bjnp-discover", "stun-info"].includes(s),
  },
  { name: "DNS", match: (s) => s.startsWith("dns-") },
  { name: "SSL / TLS", match: (s) => s.startsWith("ssl") || s.startsWith("tls-") },
  { name: "SNMP", match: (s) => s.startsWith("snmp-") },
  {
    name: "Databases",
    match: (s) =>
      s.startsWith("mysql-") || s.startsWith("ms-sql-") || s.startsWith("couchdb-") ||
      ["db2-das-info", "maxdb-info", "riak-http-info", "membase-http-info", "drda-info", "voldemort-info"].includes(s),
  },
  { name: "Big Data (Hadoop/HBase)", match: (s) => s.startsWith("hadoop-") || s.startsWith("hbase-") || ["flume-master-info", "ganglia-info"].includes(s) },
  { name: "Mail (SMTP/IMAP/POP3/NNTP)", match: (s) => s.startsWith("smtp-") || s.startsWith("imap-") || s.startsWith("pop3-") || s.startsWith("nntp-") },
  { name: "IP Geolocation", match: (s) => s.startsWith("ip-geolocation-") },
  { name: "Remote Access (RDP/VNC/Telnet)", match: (s) => s.startsWith("telnet-") || ["vnc-info", "realvnc-auth-bypass", "sstp-discover"].includes(s) },
  { name: "SMB / Windows", match: (s) => s.startsWith("smb") || s.startsWith("ncp-") || s === "nbns-interfaces" },
  { name: "Citrix", match: (s) => s.startsWith("citrix-") },
  {
    name: "Industrial / IoT",
    match: (s) =>
      s.startsWith("ipmi-") || s.startsWith("knx-gateway-") ||
      ["multicast-profinet-discovery", "openwebnet-discovery", "dicom-ping", "gpsd-info", "hddtemp-info"].includes(s),
  },
  {
    name: "App Servers (AJP/RMI/RPC)",
    match: (s) => s.startsWith("ajp-") || ["jdwp-info", "weblogic-t3-info", "eppc-enum-processes", "rmi-dumpregistry", "rpcap-info", "epmd-info"].includes(s),
  },
  { name: "Legacy Backdoors", match: (s) => s.startsWith("netbus-") || ["backorifice-info", "smb-double-pulsar-backdoor", "p2p-conficker"].includes(s) },
  { name: "Game Servers", match: (s) => s.startsWith("quake") || ["ventrilo-info", "wdb-version"].includes(s) },
  { name: "P2P / Cryptocurrency", match: (s) => s.startsWith("bitcoin") || ["bittorrent-discovery", "vuze-dht-info"].includes(s) },
  { name: "Messaging (IRC/XMPP/MQTT)", match: (s) => s.startsWith("irc-") || ["xmpp-info", "mqtt-subscribe", "amqp-info"].includes(s) },
  { name: "AFP / Apple", match: (s) => s.startsWith("afp-") },
  { name: "Time Services", match: (s) => ["daytime", "rfc868-time", "ntp-info"].includes(s) },
  { name: "Auth / Proxy Checks", match: (s) => ["auth-owners", "auth-spoof", "creds-summary", "socks-auth-info", "socks-open-proxy", "rsa-vuln-roca"].includes(s) },
  {
    name: "Network Fingerprinting / Recon",
    match: (s) =>
      ["fcrdns", "hostmap-robtex", "ipidseq", "path-mtu", "port-states", "unusual-port", "duplicates", "firewalk",
        "traceroute-geolocation", "tor-consensus-checker", "whois-domain", "whois-ip", "asn-query", "resolveall",
        "reverse-index", "ubiquiti-discovery", "ip-forwarding", "ip-https-discover", "ipv6-node-info"].includes(s),
  },
  { name: "NFS / Filesystem", match: (s) => ["nfs-ls", "nfs-statfs", "ndmp-fs-info", "iscsi-info", "isns-info"].includes(s) },
];

export interface NSEScriptGroup {
  name: string;
  scripts: string[];
}

// Groups are returned in a fixed, deterministic order (declaration order
// of CATEGORY_RULES, "Other" always last) - so the page's layout doesn't
// reshuffle between renders or reloads.
export function groupAdditionalNseScripts(scripts: string[] = ADDITIONAL_SAFE_NSE_SCRIPTS): NSEScriptGroup[] {
  const groups: NSEScriptGroup[] = CATEGORY_RULES.map((rule) => ({ name: rule.name, scripts: [] as string[] }));
  const other: string[] = [];
  for (const script of scripts) {
    const rule = CATEGORY_RULES.find((r) => r.match(script));
    if (rule) {
      groups.find((g) => g.name === rule.name)!.scripts.push(script);
    } else {
      other.push(script);
    }
  }
  const nonEmpty = groups.filter((g) => g.scripts.length > 0);
  if (other.length > 0) nonEmpty.push({ name: "Other", scripts: other });
  return nonEmpty;
}

// "Active Modules" - nmap's intrusive/exploit/brute/dos categories,
// mirrors scanner/internal/pipeline/nse_active_scripts.go and
// server/src/scanProfiles/knownNseScripts.ts exactly (regenerate all
// three together - see the Go file's doc comment for the derivation
// command). Deliberately NOT offered as a one-click profile the way
// ALL_SAFE_NSE_SCRIPTS is - these scripts can crash services, lock out
// accounts, or actively exploit a real vulnerability, so the Scan
// Profiles page only ever surfaces them as opt-in checkboxes inside a
// hand-built Custom profile, behind an explicit warning.
export const EXPLOIT_NSE_SCRIPTS: string[] = [
  "afp-path-vuln", "clamav-exec", "distcc-cve2004-2687", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor",
  "http-adobe-coldfusion-apsa1301", "http-avaya-ipoffice-users", "http-awstatstotals-exec",
  "http-axis2-dir-traversal", "http-barracuda-dir-traversal", "http-coldfusion-subzero", "http-csrf",
  "http-dlink-backdoor", "http-dombased-xss", "http-fileupload-exploiter", "http-huawei-hg5xx-vuln",
  "http-litespeed-sourcecode-download", "http-majordomo2-dir-traversal", "http-phpmyadmin-dir-traversal",
  "http-shellshock", "http-stored-xss", "http-tplink-dir-traversal", "http-vuln-cve2006-3392",
  "http-vuln-cve2009-3960", "http-vuln-cve2012-1823", "http-vuln-cve2013-0156", "http-vuln-cve2013-6786",
  "http-vuln-cve2013-7091", "http-vuln-cve2014-3704", "http-vuln-cve2014-8877", "http-vuln-cve2017-5689",
  "http-vuln-wnr1000-creds", "irc-unrealircd-backdoor", "jdwp-exec", "jdwp-inject", "qconn-exec",
  "smb-vuln-conficker", "smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029", "smb-vuln-ms08-067",
  "smb-vuln-regsvc-dos", "smb-webexec-exploit", "smtp-vuln-cve2010-4344", "supermicro-ipmi-conf",
];

export const BRUTE_NSE_SCRIPTS: string[] = [
  "afp-brute", "ajp-brute", "backorifice-brute", "cassandra-brute", "cics-enum", "cics-user-brute", "cics-user-enum",
  "citrix-brute-xml", "cvs-brute", "cvs-brute-repository", "deluge-rpc-brute", "dicom-brute", "domcon-brute",
  "dpap-brute", "drda-brute", "ftp-brute", "http-brute", "http-form-brute", "http-iis-short-name-brute",
  "http-joomla-brute", "http-proxy-brute", "http-wordpress-brute", "iax2-brute", "imap-brute",
  "impress-remote-discover", "informix-brute", "ipmi-brute", "irc-brute", "irc-sasl-brute", "iscsi-brute",
  "ldap-brute", "lu-enum", "membase-brute", "metasploit-msgrpc-brute", "metasploit-xmlrpc-brute",
  "mikrotik-routeros-brute", "mmouse-brute", "mongodb-brute", "ms-sql-brute", "mysql-brute", "mysql-enum",
  "nessus-brute", "nessus-xmlrpc-brute", "netbus-brute", "nexpose-brute", "nje-node-brute", "nje-pass-brute",
  "nping-brute", "omp2-brute", "openvas-otp-brute", "oracle-brute", "oracle-brute-stealth", "oracle-sid-brute",
  "pcanywhere-brute", "pgsql-brute", "pop3-brute", "redis-brute", "rexec-brute", "rlogin-brute", "rpcap-brute",
  "rsync-brute", "rtsp-url-brute", "sip-brute", "smb-brute", "smtp-brute", "snmp-brute", "socks-brute", "ssh-brute",
  "svn-brute", "telnet-brute", "tso-enum", "vmauthd-brute", "vnc-brute", "vtam-enum", "xmpp-brute",
];

export const DOS_NSE_SCRIPTS: string[] = [
  "broadcast-avahi-dos", "http-slowloris", "ipv6-ra-flood", "smb-flood", "smb-vuln-conficker",
  "smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029", "smb-vuln-ms08-067", "smb-vuln-ms10-054",
  "smb-vuln-regsvc-dos",
];

export const OTHER_INTRUSIVE_NSE_SCRIPTS: string[] = [
  "dns-brute", "dns-cache-snoop", "dns-fuzz", "dns-ip6-arpa-scan", "dns-nsec-enum", "dns-nsec3-enum",
  "dns-random-srcport", "dns-random-txid", "dns-update", "dns-zone-transfer", "domcon-cmd", "domino-enum-users",
  "firewall-bypass", "ftp-libopie", "ftp-vuln-cve2010-4221", "hartip-info", "http-chrono", "http-config-backup",
  "http-default-accounts", "http-devframework", "http-domino-enum-passwords", "http-drupal-enum",
  "http-drupal-enum-users", "http-enum", "http-errors", "http-exif-spider", "http-feed", "http-form-fuzzer",
  "http-iis-webdav-vuln", "http-open-redirect", "http-passwd", "http-phpself-xss", "http-put", "http-rfi-spider",
  "http-sitemap-generator", "http-sql-injection", "http-unsafe-output-escaping", "http-userdir-enum", "http-vhosts",
  "http-vuln-cve2010-2861", "http-vuln-cve2011-3368", "http-vuln-cve2015-1427", "http-vuln-cve2017-8917",
  "http-vuln-misfortune-cookie", "http-waf-detect", "http-waf-fingerprint", "http-wordpress-enum",
  "http-wordpress-users", "iec-identify", "iec61850-mms", "informix-query", "informix-tables", "krb5-enum-users",
  "metasploit-info", "mmouse-exec", "modbus-discover", "ms-sql-empty-password", "ms-sql-xp-cmdshell",
  "mysql-databases", "mysql-empty-password", "mysql-users", "mysql-variables", "mysql-vuln-cve2012-2122", "nbd-info",
  "nrpe-enum", "ntp-monlist", "oracle-enum-users", "pjl-ready-message", "profinet-cm-lookup", "puppet-naivesigning",
  "rdp-vuln-ms12-020", "rmi-vuln-classloader", "samba-vuln-cve-2012-1182", "sip-call-spoof", "sip-enum-users",
  "smb-enum-domains", "smb-enum-groups", "smb-enum-processes", "smb-enum-services", "smb-enum-sessions",
  "smb-enum-users", "smb-print-text", "smb-psexec", "smb-server-stats", "smb-system-info", "smb-vuln-cve-2017-7494",
  "smb-vuln-ms10-061", "smb-vuln-webexec", "smtp-enum-users", "smtp-vuln-cve2011-1720", "smtp-vuln-cve2011-1764",
  "sniffer-detect", "snmp-ios-config", "ssh-auth-methods", "ssh-publickey-acceptance", "ssh-run", "ssl-enum-ciphers",
  "sslv2-drown", "stuxnet-detect", "tftp-enum", "tso-brute", "vnc-title",
];

// Fixed four named groups (unlike groupAdditionalNseScripts, no
// prefix-matching heuristic needed - nmap's own intrusive/exploit/
// brute/dos categories already give a clean, meaningful split).
export function groupActiveNseScripts(): NSEScriptGroup[] {
  return [
    { name: "Exploit", scripts: EXPLOIT_NSE_SCRIPTS },
    { name: "Brute-force", scripts: BRUTE_NSE_SCRIPTS },
    { name: "Denial of Service", scripts: DOS_NSE_SCRIPTS },
    { name: "Other Intrusive", scripts: OTHER_INTRUSIVE_NSE_SCRIPTS },
  ];
}
