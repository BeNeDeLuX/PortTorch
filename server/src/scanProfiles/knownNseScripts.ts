// A second, TS-side copy of the scanner's NSE script lists
// (scanner/internal/pipeline/nse_default_scripts.go/nse_safe_scripts.go)
// - used ONLY for the Scan Profiles admin page's checkbox options and for
// rejecting a typo'd/unrecognized script name at profile-creation time
// with a 400 (see routes.ts), never for execution. The canonical,
// executed lists live exclusively in the Go scanner (see those files'
// own doc comments for why - avoids the exact "http-elasticsearch" class
// of risk CLAUDE.md documents from being reintroduced by a second,
// independently-maintained executable copy). Regenerate both together -
// see nse_safe_scripts.go's doc comment for the derivation command.

// Exactly today's historical hardcoded --script= list (RunNmap's
// "Default" profile) - unchanged content, just now selectable by name.
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

// "All Safe Modules" - nmap's own "safe and not intrusive" NSE category,
// unioned with DEFAULT_NSE_SCRIPTS (three Default scripts - smb-enum-shares,
// smtp-open-relay, docker-version - aren't actually nmap-tagged "safe",
// so a plain swap would silently regress them; see nse_safe_scripts.go).
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

// "Active Modules" - nmap's intrusive/exploit/brute/dos categories, split
// into four subcategories (mirrors nse_active_scripts.go's doc comment
// for the full "why" and the derivation command). Deliberately NOT a
// one-click profile kind like ALL_SAFE_NSE_SCRIPTS - these scripts can
// crash services, lock out accounts, or actively exploit a real
// vulnerability, so they're only ever reachable by hand-picking specific
// scripts into a named Custom profile. Each already excludes anything in
// DEFAULT_NSE_SCRIPTS (nothing to add there).
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

// Validation/UI allowlist for Custom profiles - the union of every list
// above (deduplicated by Set).
export const KNOWN_NSE_SCRIPTS: Set<string> = new Set([
  ...DEFAULT_NSE_SCRIPTS,
  ...ALL_SAFE_NSE_SCRIPTS,
  ...EXPLOIT_NSE_SCRIPTS,
  ...BRUTE_NSE_SCRIPTS,
  ...DOS_NSE_SCRIPTS,
  ...OTHER_INTRUSIVE_NSE_SCRIPTS,
]);
