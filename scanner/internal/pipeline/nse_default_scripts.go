package pipeline

// DefaultNSEScripts is the "Default" scan profile's TCP script list -
// exactly the set RunNmap has always unconditionally run (see nmap.go's
// own doc comment for why each entry is here), extracted into its own
// named list so it can be selected explicitly (as opposed to only ever
// being the hardcoded, unconfigurable --script= value it used to be).
// Order preserved from nmap.go's original --script= string for easy
// diffing against history; RunNmap itself no longer cares about order.
var DefaultNSEScripts = []string{
	"banner", "ssh-hostkey", "ftp-anon", "smb-enum-shares",
	"smb-os-discovery", "nbstat", "smb-protocols", "smb-security-mode", "smb2-security-mode",
	"nfs-showmount", "rsync-list-modules", "ldap-rootdse",
	"mongodb-info", "mongodb-databases", "redis-info", "mysql-info", "memcached-info", "oracle-tns-version",
	"docker-version", "couchdb-databases", "cassandra-info", "smtp-open-relay",
	"http-methods", "http-auth", "http-git",
	"rdp-ntlm-info", "rdp-enum-encryption", "ssh2-enum-algos", "sshv1",
	"rpcinfo", "msrpc-enum",
}
