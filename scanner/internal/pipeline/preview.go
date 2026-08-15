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
		}
		return result, nil
	}

	result.AppliedIPExcludes = excludes.IPs
	if parsed := net.ParseIP(strings.TrimSpace(targetSpec)); parsed != nil {
		excluded, reason := isTargetExcluded(targetSpec, excludes.IPs)
		result.SingleIPv4Target = &TargetPreview{IP: targetSpec, Excluded: excluded, Reason: reason}
	}
	return result, nil
}
