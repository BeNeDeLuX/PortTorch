package pipeline

// "Active Modules" - nmap's own intrusive/exploit/brute/dos NSE
// categories, deliberately NOT a fourth one-click scan profile kind
// alongside "default"/"all_safe" (there is no ActiveNSEScripts constant
// used by RunScan/resolveNSEScripts anywhere, and no "active" value in
// scan_requests.nse_profile's CHECK constraint) - unlike "All Safe
// Modules", these scripts can crash services, lock out accounts, or
// actively exploit a real vulnerability, so there is no whole-fleet
// "just turn it on" toggle for them. They're only ever reachable by an
// admin hand-picking specific scripts into a named Custom profile (see
// CLAUDE.md's Scan Profiles section) - these four lists exist purely so
// server/src/scanProfiles/knownNseScripts.ts (the Custom-profile
// validation allowlist) and the frontend checkbox UI have an
// authoritative, reviewed set of script names to offer, same
// "canonical-in-Go, cross-verified elsewhere" discipline as
// DefaultNSEScripts/AllSafeNSEScripts - never executed via any special
// profile-kind branch, only ever as part of whatever arbitrary script
// list a Custom profile snapshot already carries.
//
// Split into four subcategories (rather than one flat list) so the
// Scan Profiles page can show each with its own "select all" checkbox
// and let an admin consciously pick, say, brute-force checks without
// also pulling in denial-of-service scripts - nmap's own categories
// are non-exclusive tags, not a partition, so "OtherIntrusive" is
// everything tagged "intrusive" that isn't already exploit/brute/dos.
// All four are deduplicated against DefaultNSEScripts (a script already
// always-included has nothing to add here) - captured the same way as
// AllSafeNSEScripts, by reading a real nmap 7.95 install's own
// script.db directly:
//
//	python3 -c '
//	import re
//	entries = re.findall(r"Entry \{ filename = \"([^\"]+)\.nse\", categories = \{([^}]*)\} \}",
//	                      open("/usr/share/nmap/scripts/script.db").read())
//	by_cat = {c: set() for c in ("intrusive","exploit","brute","dos")}
//	for f, cats in entries:
//	    tags = {c.strip().strip(chr(34)) for c in cats.split(",") if c.strip()}
//	    for c in by_cat:
//	        if c in tags: by_cat[c].add(f)
//	exploit, brute, dos = by_cat["exploit"], by_cat["brute"], by_cat["dos"]
//	other_intrusive = by_cat["intrusive"] - exploit - brute - dos
//	'
//
// To refresh for a newer nmap release: re-run against the new
// script.db, diff each of the four lists, and manually review every
// addition/removal before updating - same reviewed-list philosophy as
// RunNmap's own --script list and AllSafeNSEScripts (see nmap.go's doc
// comment and CLAUDE.md's "http-elasticsearch" incident).
var ExploitNSEScripts = []string{
	"afp-path-vuln", "clamav-exec", "distcc-cve2004-2687", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor",
	"http-adobe-coldfusion-apsa1301", "http-avaya-ipoffice-users", "http-awstatstotals-exec",
	"http-axis2-dir-traversal", "http-barracuda-dir-traversal", "http-coldfusion-subzero", "http-csrf",
	"http-dlink-backdoor", "http-dombased-xss", "http-fileupload-exploiter", "http-huawei-hg5xx-vuln",
	"http-litespeed-sourcecode-download", "http-majordomo2-dir-traversal", "http-phpmyadmin-dir-traversal",
	"http-shellshock", "http-stored-xss", "http-tplink-dir-traversal", "http-vuln-cve2006-3392",
	"http-vuln-cve2009-3960", "http-vuln-cve2012-1823", "http-vuln-cve2013-0156", "http-vuln-cve2013-6786",
	"http-vuln-cve2013-7091", "http-vuln-cve2014-3704", "http-vuln-cve2014-8877", "http-vuln-cve2017-5689",
	"http-vuln-wnr1000-creds", "irc-unrealircd-backdoor", "jdwp-exec", "jdwp-inject", "qconn-exec",
	"smb-vuln-conficker", "smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029",
	"smb-vuln-ms08-067", "smb-vuln-regsvc-dos", "smb-webexec-exploit", "smtp-vuln-cve2010-4344",
	"supermicro-ipmi-conf",
}

var BruteNSEScripts = []string{
	"afp-brute", "ajp-brute", "backorifice-brute", "cassandra-brute", "cics-enum", "cics-user-brute",
	"cics-user-enum", "citrix-brute-xml", "cvs-brute", "cvs-brute-repository", "deluge-rpc-brute",
	"dicom-brute", "domcon-brute", "dpap-brute", "drda-brute", "ftp-brute", "http-brute", "http-form-brute",
	"http-iis-short-name-brute", "http-joomla-brute", "http-proxy-brute", "http-wordpress-brute", "iax2-brute",
	"imap-brute", "impress-remote-discover", "informix-brute", "ipmi-brute", "irc-brute", "irc-sasl-brute",
	"iscsi-brute", "ldap-brute", "lu-enum", "membase-brute", "metasploit-msgrpc-brute",
	"metasploit-xmlrpc-brute", "mikrotik-routeros-brute", "mmouse-brute", "mongodb-brute", "ms-sql-brute",
	"mysql-brute", "mysql-enum", "nessus-brute", "nessus-xmlrpc-brute", "netbus-brute", "nexpose-brute",
	"nje-node-brute", "nje-pass-brute", "nping-brute", "omp2-brute", "openvas-otp-brute", "oracle-brute",
	"oracle-brute-stealth", "oracle-sid-brute", "pcanywhere-brute", "pgsql-brute", "pop3-brute", "redis-brute",
	"rexec-brute", "rlogin-brute", "rpcap-brute", "rsync-brute", "rtsp-url-brute", "sip-brute", "smb-brute",
	"smtp-brute", "snmp-brute", "socks-brute", "ssh-brute", "svn-brute", "telnet-brute", "tso-enum",
	"vmauthd-brute", "vnc-brute", "vtam-enum", "xmpp-brute",
}

var DosNSEScripts = []string{
	"broadcast-avahi-dos", "http-slowloris", "ipv6-ra-flood", "smb-flood", "smb-vuln-conficker",
	"smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029", "smb-vuln-ms08-067", "smb-vuln-ms10-054",
	"smb-vuln-regsvc-dos",
}

var OtherIntrusiveNSEScripts = []string{
	"dns-brute", "dns-cache-snoop", "dns-fuzz", "dns-ip6-arpa-scan", "dns-nsec-enum", "dns-nsec3-enum",
	"dns-random-srcport", "dns-random-txid", "dns-update", "dns-zone-transfer", "domcon-cmd",
	"domino-enum-users", "firewall-bypass", "ftp-libopie", "ftp-vuln-cve2010-4221", "hartip-info",
	"http-chrono", "http-config-backup", "http-default-accounts", "http-devframework",
	"http-domino-enum-passwords", "http-drupal-enum", "http-drupal-enum-users", "http-enum", "http-errors",
	"http-exif-spider", "http-feed", "http-form-fuzzer", "http-iis-webdav-vuln", "http-open-redirect",
	"http-passwd", "http-phpself-xss", "http-put", "http-rfi-spider", "http-sitemap-generator",
	"http-sql-injection", "http-unsafe-output-escaping", "http-userdir-enum", "http-vhosts",
	"http-vuln-cve2010-2861", "http-vuln-cve2011-3368", "http-vuln-cve2015-1427", "http-vuln-cve2017-8917",
	"http-vuln-misfortune-cookie", "http-waf-detect", "http-waf-fingerprint", "http-wordpress-enum",
	"http-wordpress-users", "iec-identify", "iec61850-mms", "informix-query", "informix-tables",
	"krb5-enum-users", "metasploit-info", "mmouse-exec", "modbus-discover", "ms-sql-empty-password",
	"ms-sql-xp-cmdshell", "mysql-databases", "mysql-empty-password", "mysql-users", "mysql-variables",
	"mysql-vuln-cve2012-2122", "nbd-info", "nrpe-enum", "ntp-monlist", "oracle-enum-users", "pjl-ready-message",
	"profinet-cm-lookup", "puppet-naivesigning", "rdp-vuln-ms12-020", "rmi-vuln-classloader",
	"samba-vuln-cve-2012-1182", "sip-call-spoof", "sip-enum-users", "smb-enum-domains", "smb-enum-groups",
	"smb-enum-processes", "smb-enum-services", "smb-enum-sessions", "smb-enum-users", "smb-print-text",
	"smb-psexec", "smb-server-stats", "smb-system-info", "smb-vuln-cve-2017-7494", "smb-vuln-ms10-061",
	"smb-vuln-webexec", "smtp-enum-users", "smtp-vuln-cve2011-1720", "smtp-vuln-cve2011-1764", "sniffer-detect",
	"snmp-ios-config", "ssh-auth-methods", "ssh-publickey-acceptance", "ssh-run", "ssl-enum-ciphers",
	"sslv2-drown", "stuxnet-detect", "tftp-enum", "tso-brute", "vnc-title",
}

// AllActiveNSEScripts is the union of all four Active Modules
// subcategories - used only by knownNseScripts.ts's validation
// allowlist (via its own equivalent union) and nseScripts.ts's frontend
// listing, never by the scanner itself for execution (see the package
// doc comment above).
var AllActiveNSEScripts = dedupSorted(append(append(append(
	append([]string{}, ExploitNSEScripts...), BruteNSEScripts...), DosNSEScripts...), OtherIntrusiveNSEScripts...))
