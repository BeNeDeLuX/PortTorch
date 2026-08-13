package pipeline

import "sort"

// AllSafeNSEScripts is the "All Safe Modules" scan profile's TCP script
// list - every NSE script nmap itself categorizes as "safe" and NOT also
// "intrusive" (categories are non-exclusive tags in nmap's own script
// metadata, not a strict partition - a script can be tagged both "safe"
// and "intrusive" at once, e.g. metasploit-info and smb-enum-services,
// so filtering on "safe" alone would wrongly include those two),
// unioned with DefaultNSEScripts.
//
// The union matters: three of Default's own 31 scripts - smb-enum-shares,
// smtp-open-relay, docker-version - are NOT tagged "safe" by nmap's own
// script.db despite being safe in practice (read-only, no credentials,
// the same reasoning that put them in Default in the first place - see
// nmap.go's RunNmap doc comment). Without the union, switching from
// Default to "All Safe Modules" would silently drop those three - a
// "broader" profile that actually finds less than the narrower one it
// replaced. Confirmed directly against nmap 7.95's own script.db, not
// assumed:
//
//	smb-enum-shares  -> categories: discovery, intrusive   (no "safe" tag at all)
//	smtp-open-relay  -> categories: discovery, external, intrusive (no "safe" tag at all)
//	docker-version   -> categories: version                 (no "safe" tag at all)
//
// Captured once from a real nmap 7.95 install by reading its own
// script.db directly (categories = { ... } per script) rather than
// parsing --script-help's free-text output for all ~600 scripts:
//
//	python3 -c '
//	import re
//	entries = re.findall(r"Entry \{ filename = \"([^\"]+)\.nse\", categories = \{([^}]*)\} \}",
//	                      open("/usr/share/nmap/scripts/script.db").read())
//	safe = sorted({f for f, c in entries
//	               if "safe" in c and "intrusive" not in c})
//	print(",".join(safe))
//	'
//
// To refresh for a newer nmap release: re-run the same script against
// the new install's script.db, diff the result against this list, and
// manually review every addition/removal before updating it here - same
// "explicit, reviewed script list" philosophy as RunNmap's own --script
// list (see nmap.go's doc comment and CLAUDE.md's "http-elasticsearch"
// incident - a bad or since-renamed script name is fatal to the entire
// nmap invocation, not just to that one script, so this list is never
// derived dynamically at scan time).
//
// server/src/scanProfiles/knownNseScripts.ts holds a second, TS-side copy
// of this same list - but only as a Custom-profile UI checkbox/validation
// allowlist, never for execution (see that file's own comment). Regenerate
// both together.
var AllSafeNSEScripts = dedupSorted(append(append([]string{}, DefaultNSEScripts...), []string{
	"acarsd-info", "address-info", "afp-ls", "afp-serverinfo", "afp-showmount", "ajp-auth", "ajp-headers",
	"ajp-methods", "ajp-request", "allseeingeye-info", "amqp-info", "asn-query", "auth-owners", "auth-spoof",
	"backorifice-info", "banner", "bitcoin-getaddr", "bitcoin-info", "bitcoinrpc-info", "bittorrent-discovery",
	"bjnp-discover", "broadcast-ataoe-discover", "broadcast-bjnp-discover", "broadcast-db2-discover",
	"broadcast-dhcp-discover", "broadcast-dhcp6-discover", "broadcast-dns-service-discovery",
	"broadcast-dropbox-listener", "broadcast-eigrp-discovery", "broadcast-hid-discoveryd", "broadcast-igmp-discovery",
	"broadcast-jenkins-discover", "broadcast-listener", "broadcast-ms-sql-discover",
	"broadcast-netbios-master-browser", "broadcast-networker-discover", "broadcast-novell-locate",
	"broadcast-ospf2-discover", "broadcast-pc-anywhere", "broadcast-pc-duo", "broadcast-pim-discovery",
	"broadcast-ping", "broadcast-pppoe-discover", "broadcast-rip-discover", "broadcast-ripng-discover",
	"broadcast-sonicwall-discover", "broadcast-sybase-asa-discover", "broadcast-tellstick-discover",
	"broadcast-upnp-info", "broadcast-versant-locate", "broadcast-wake-on-lan", "broadcast-wpad-discover",
	"broadcast-wsdd-discover", "broadcast-xdmcp-discover", "cassandra-info", "cics-info", "citrix-enum-apps",
	"citrix-enum-apps-xml", "citrix-enum-servers", "citrix-enum-servers-xml", "clock-skew", "coap-resources",
	"couchdb-databases", "couchdb-stats", "creds-summary", "cups-info", "cups-queue-info", "daap-get-library",
	"daytime", "db2-das-info", "dhcp-discover", "dicom-ping", "dict-info", "dns-blacklist", "dns-check-zone",
	"dns-client-subnet-scan", "dns-nsid", "dns-recursion", "dns-service-discovery", "dns-srv-enum", "dns-zeustracker",
	"docker-version", "drda-info", "duplicates", "eap-info", "epmd-info", "eppc-enum-processes", "fcrdns", "finger",
	"firewalk", "flume-master-info", "freelancer-info", "ftp-anon", "ftp-bounce", "ftp-syst", "ganglia-info",
	"giop-info", "gkrellm-info", "gopher-ls", "gpsd-info", "hadoop-datanode-info", "hadoop-jobtracker-info",
	"hadoop-namenode-info", "hadoop-secondary-namenode-info", "hadoop-tasktracker-info", "hbase-master-info",
	"hbase-region-info", "hddtemp-info", "hnap-info", "hostmap-robtex", "http-affiliate-id",
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
	"openlookup-info", "openwebnet-discovery", "oracle-tns-version", "p2p-conficker", "path-mtu", "pop3-capabilities",
	"pop3-ntlm-info", "port-states", "qscan", "quake1-info", "quake3-info", "quake3-master-getservers",
	"rdp-enum-encryption", "rdp-ntlm-info", "realvnc-auth-bypass", "redis-info", "resolveall", "reverse-index",
	"rfc868-time", "riak-http-info", "rmi-dumpregistry", "rpcap-info", "rpcinfo", "rsa-vuln-roca",
	"rsync-list-modules", "rtsp-methods", "rusers", "servicetags", "shodan-api", "sip-methods",
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
}...))

// dedupSorted returns a sorted copy of items with duplicates removed -
// used once, at package init, to build AllSafeNSEScripts from
// DefaultNSEScripts ∪ nmap's safe-and-not-intrusive category (the two
// sets overlap on every Default script that's also nmap-tagged safe, so
// simple concatenation would otherwise list e.g. "banner" twice).
func dedupSorted(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}
