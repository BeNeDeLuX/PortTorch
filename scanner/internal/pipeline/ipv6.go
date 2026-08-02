package pipeline

import (
	"fmt"
	"net"
	"strings"
)

// parseIPv6TargetList splits targetSpec on "," and requires every piece to
// be a bare IPv6 address - no CIDR, no "start-end" range. Unlike IPv4,
// where masscan can cheaply sweep a whole /24, IPv6 address space is far
// too large to brute-force scan a range/CIDR at all, so this deliberately
// only supports scanning specific, already-known addresses (which is also
// how real IPv6 asset inventories actually work - DNS/NDP/DHCPv6 records,
// not a sweep). Returns a clear error rather than silently misbehaving if
// the spec looks IPv6-flavored but isn't a plain address list (e.g. someone
// tried a CIDR or range).
func parseIPv6TargetList(targetSpec string) ([]string, error) {
	parts := strings.Split(targetSpec, ",")
	ips := make([]string, 0, len(parts))
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		parsed := net.ParseIP(addr)
		if parsed == nil || parsed.To4() != nil {
			return nil, fmt.Errorf(
				"IPv6 scanning only supports a single address or a comma-separated list of addresses, not a CIDR or range (%q)",
				addr,
			)
		}
		ips = append(ips, addr)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv6 targets found in %q", targetSpec)
	}
	return ips, nil
}

// isTargetExcluded reports whether ip matches any entry in ipExcludes
// (bare addresses or CIDRs, the same list masscan's --excludefile would
// otherwise enforce for IPv4). There's no masscan step in the IPv6
// discovery path, so this check has to happen here instead. Entries that
// don't parse as either a CIDR or a bare IP (e.g. an IPv4 "start-end"
// range, which can never match an IPv6 address anyway) are simply skipped,
// not treated as errors - matching filterIPPortExcludes' tolerance of
// values it can't apply.
func isTargetExcluded(ip string, ipExcludes []string) (bool, string) {
	target := net.ParseIP(ip)
	for _, entry := range ipExcludes {
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			if ipNet.Contains(target) {
				return true, entry
			}
			continue
		}
		if excluded := net.ParseIP(entry); excluded != nil && excluded.Equal(target) {
			return true, entry
		}
	}
	return false, ""
}
