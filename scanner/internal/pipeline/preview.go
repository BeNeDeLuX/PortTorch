package pipeline

import (
	"fmt"
	"net"
	"strings"
)

// TargetPreview is one address's exclude-check result - used for both the
// IPv6 target list (every address, since it's always fully enumerable)
// and a single bare IPv4 target (the one IPv4 case resolvable without
// actually running masscan - see PreviewResult.SingleIPv4Target).
type TargetPreview struct {
	IP       string
	Excluded bool
	// Reason is the exact exclude entry (a CIDR or bare address) that
	// matched - "" when Excluded is false.
	Reason string
}

// PreviewResult is a dry-run summary of what RunScan would actually do
// with this exact target/port spec and exclude list, computed without
// invoking masscan or nmap - see PreviewScan.
type PreviewResult struct {
	TargetSpec string
	PortSpec   string
	// EffectivePortSpec is what nmap/masscan would actually be asked to
	// scan, after subtracting every port/port-range exclude - "" means
	// every requested port is excluded, so nothing would be scanned at
	// all (mirrors RunScan's own "nothing to scan" short-circuit).
	EffectivePortSpec string

	// AddressCount is how many addresses the target spec covers, which is
	// the number that decides whether a scan is a minute or a weekend.
	// 0 means "not countable" - a hostname, which only DNS at scan time
	// can resolve.
	AddressCount int64

	IsIPv6 bool
	// IPv6Targets is one entry per address in the comma-separated target
	// list, in order - populated only when IsIPv6 is true, since that
	// target form is always a small, fully enumerable list (see
	// parseIPv6TargetList's own doc comment on why IPv6 scanning is
	// address-list-only, never a CIDR/range sweep).
	IPv6Targets []TargetPreview

	// SingleIPv4Target is set only when TargetSpec is a single bare IPv4
	// address, not a CIDR/range - the one IPv4 case a preview can
	// resolve definitively, since a CIDR/range is usually far too large
	// to enumerate and is instead handled by AppliedIPExcludes below,
	// exactly like masscan's own --excludefile does at scan time.
	SingleIPv4Target *TargetPreview
	// AppliedIPExcludes lists exactly the IP/CIDR/range exclude entries
	// that would be passed to masscan's --excludefile for this scan
	// (already the union of global and this-scanner-scoped excludes
	// resolved by GetExcludes) - populated only for the IPv4 CIDR/range
	// case, where this is the most a preview can say without actually
	// running masscan.
	AppliedIPExcludes []string

	// IPPortExcludes lists the "ip:portSpec" excludes that would be
	// applied to results after discovery (filterIPPortExcludes) - shown
	// as an informational list rather than resolved against anything
	// above, since which hosts actually get discovered isn't known yet.
	IPPortExcludes []string
}

// PreviewScan computes what RunScan would actually target, given the same
// target/port spec and already-fetched excludes, without invoking masscan
// or nmap. Deliberately reuses RunScan's own unexported helpers
// (subtractPorts, isTargetExcluded, parseIPv6TargetList) rather than
// re-implementing exclude logic a second time, so a preview can never
// drift from what a real scan would actually do.
func PreviewScan(targetSpec, portSpec string, excludes Excludes) (*PreviewResult, error) {
	effectivePortSpec, err := subtractPorts(portSpec, excludes.Ports)
	if err != nil {
		return nil, err
	}

	result := &PreviewResult{
		TargetSpec:        targetSpec,
		PortSpec:          portSpec,
		EffectivePortSpec: effectivePortSpec,
	}
	for _, ex := range excludes.IPPorts {
		result.IPPortExcludes = append(result.IPPortExcludes, fmt.Sprintf("%s:%s", ex.IP, ex.PortSpec))
	}

	if strings.Contains(targetSpec, ":") {
		result.IsIPv6 = true
		ips, err := parseIPv6TargetList(targetSpec)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			excluded, reason := isTargetExcluded(ip, excludes.IPs)
			result.IPv6Targets = append(result.IPv6Targets, TargetPreview{IP: ip, Excluded: excluded, Reason: reason})
			// An IPv6 target is always an explicit address list (see
			// parseIPv6TargetList), so excluded ones can be subtracted
			// exactly rather than estimated - unlike a v4 CIDR, where
			// masscan applies the excludes itself at scan time.
			if !excluded {
				result.AddressCount++
			}
		}
		return result, nil
	}

	result.AppliedIPExcludes = excludes.IPs
	result.AddressCount = CountAddresses(targetSpec)
	if parsed := net.ParseIP(strings.TrimSpace(targetSpec)); parsed != nil {
		excluded, reason := isTargetExcluded(targetSpec, excludes.IPs)
		result.SingleIPv4Target = &TargetPreview{IP: targetSpec, Excluded: excluded, Reason: reason}
	}
	return result, nil
}

// CountAddresses is how many addresses an IPv4 target spec covers, across
// every form masscan's own grammar accepts here: a comma-separated list
// of single addresses, CIDRs and start-end ranges. Returns 0 for anything
// it cannot count exactly - a hostname, which only the scanner's own DNS
// can resolve at scan time, so guessing 1 would be a claim rather than a
// count.
//
// Deliberately does not subtract IP excludes: masscan applies those
// itself via --excludefile, and how many addresses a /8 exclude removes
// from a /16 target is not something this can answer without enumerating
// both. The excludes are listed separately right above this in the dry
// run, which is the honest presentation.
func CountAddresses(targetSpec string) int64 {
	var total int64
	for _, part := range strings.Split(targetSpec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch {
		case strings.Contains(part, "/"):
			_, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return 0
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 {
				return 0
			}
			total += int64(1) << uint(bits-ones)
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			start, end := net.ParseIP(strings.TrimSpace(bounds[0])), net.ParseIP(strings.TrimSpace(bounds[1]))
			if start == nil || end == nil || start.To4() == nil || end.To4() == nil {
				return 0
			}
			s, e := ipToUint32(start.To4()), ipToUint32(end.To4())
			if e < s {
				return 0
			}
			total += int64(e-s) + 1
		default:
			if ip := net.ParseIP(part); ip == nil || ip.To4() == nil {
				return 0
			}
			total++
		}
	}
	return total
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// CountPorts is how many ports a spec covers, counting each protocol
// separately - "T:80,U:80" is two probes, not one, which is what the
// runtime estimate needs. Returns 0 for an unparseable spec rather than
// a guess.
func CountPorts(portSpec string) int {
	set, err := parseProtoPortSet(portSpec)
	if err != nil {
		return 0
	}
	return len(set)
}
