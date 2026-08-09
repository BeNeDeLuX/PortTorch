package pipeline

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Excludes holds IPs/CIDR ranges and ports/port ranges that must never be
// scanned. Fetched from the webserver's central list (see
// client.Client.GetExcludes) so every scanner instance - "scan" CLI, "menu"
// TUI, or "serve" - enforces the same list, regardless of entry point.
type Excludes struct {
	IPs     []string
	Ports   []string
	IPPorts []IPPortExclude
}

// IPPortExclude excludes a specific port (or port range) on one specific
// IP - unlike IPs/Ports above, neither masscan's --excludefile (whole
// IPs/CIDRs/ranges only) nor its port spec (applies uniformly to every
// target) can express "skip this port on this one host but scan it
// elsewhere", so this can't be applied before masscan runs. Instead
// filterIPPortExcludes drops matching results after masscan - masscan
// still sends its probe to that exact host:port, the exclude just means
// nothing downstream of masscan (nmap onward) ever sees a match.
type IPPortExclude struct {
	IP       string
	PortSpec string
}

// writeExcludeFile writes one IP/CIDR entry per line for masscan's
// --excludefile flag (masscan applies these even to addresses inside the
// primary target range, so an excluded /32 inside a scanned /24 is still
// skipped). Returns "" if there's nothing to exclude.
func writeExcludeFile(ips []string) (string, error) {
	if len(ips) == 0 {
		return "", nil
	}
	f, err := os.CreateTemp("", "masscan-exclude-*.conf")
	if err != nil {
		return "", fmt.Errorf("temp file for masscan excludes: %w", err)
	}
	defer f.Close()
	for _, ip := range ips {
		if _, err := fmt.Fprintln(f, ip); err != nil {
			return "", fmt.Errorf("writing masscan exclude file: %w", err)
		}
	}
	return f.Name(), nil
}

const maxPort = 65535

// subtractPorts removes excludePorts from spec (both comma-separated lists
// of single ports or "start-end" ranges) and re-serializes the remainder
// into a compact masscan-compatible spec. masscan has no native port-exclude
// flag (unlike --excludefile for IPs), so this is done ourselves before
// ever invoking masscan - nmap only sees the ports masscan reports, so a
// port excluded here never reaches nmap either. Returns "" if nothing is
// left to scan.
func subtractPorts(spec string, excludePorts []string) (string, error) {
	included, err := parsePortSet(spec)
	if err != nil {
		return "", fmt.Errorf("parsing port spec %q: %w", spec, err)
	}
	excluded, err := parsePortSet(strings.Join(excludePorts, ","))
	if err != nil {
		return "", fmt.Errorf("parsing excluded ports: %w", err)
	}
	for port := range excluded {
		delete(included, port)
	}
	return serializePortSet(included), nil
}

// filterIPPortExcludes removes masscan results matching an IP+port
// exclude, in place on the discovered map (keyed by IP), and returns how
// many individual port results were dropped (for progress logging). An
// IP whose every port gets excluded is removed from the map entirely, so
// it's correctly reported as "not found" rather than as a host with zero
// ports.
func filterIPPortExcludes(discovered map[string][]PortResult, excludes []IPPortExclude) int {
	removed := 0
	for _, ex := range excludes {
		ports, ok := discovered[ex.IP]
		if !ok {
			continue
		}
		excludedPorts, err := parsePortSet(ex.PortSpec)
		if err != nil {
			// Already validated server-side when the exclude was created -
			// a parse failure here would mean the webserver sent something
			// malformed, not worth aborting the whole scan over.
			continue
		}
		kept := ports[:0]
		for _, p := range ports {
			if _, isExcluded := excludedPorts[p.Port]; isExcluded {
				removed++
				continue
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			delete(discovered, ex.IP)
		} else {
			discovered[ex.IP] = kept
		}
	}
	return removed
}

// isPortExcludedForHost reports whether port on ip is covered by either a
// global port exclude (excludes.Ports) or an ip+port exclude scoped to
// this specific ip (excludes.IPPorts). Used by the SNMP probe (snmp.go),
// which bypasses the normal masscan -> subtractPorts -> filterIPPortExcludes
// pipeline entirely - UDP/161 is never part of the requested TCP port
// spec, so none of those three exclude mechanisms would otherwise ever
// see it. A parse failure on either side is treated as "not excluded"
// rather than aborting the scan - both were already validated
// server-side when the exclude was created, same tolerance
// filterIPPortExcludes above already applies to a malformed IPPortExclude.
func isPortExcludedForHost(ip string, port int, excludes Excludes) bool {
	if globalPorts, err := parsePortSet(strings.Join(excludes.Ports, ",")); err == nil {
		if _, excluded := globalPorts[port]; excluded {
			return true
		}
	}
	for _, ex := range excludes.IPPorts {
		if ex.IP != ip {
			continue
		}
		if scopedPorts, err := parsePortSet(ex.PortSpec); err == nil {
			if _, excluded := scopedPorts[port]; excluded {
				return true
			}
		}
	}
	return false
}

func parsePortSet(spec string) (map[int]struct{}, error) {
	set := make(map[int]struct{})
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return set, nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if before, after, ok := strings.Cut(part, "-"); ok {
			lo, errLo := strconv.Atoi(strings.TrimSpace(before))
			hi, errHi := strconv.Atoi(strings.TrimSpace(after))
			if errLo != nil || errHi != nil || lo < 1 || hi > maxPort || lo > hi {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := lo; p <= hi; p++ {
				set[p] = struct{}{}
			}
		} else {
			p, errP := strconv.Atoi(part)
			if errP != nil || p < 1 || p > maxPort {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			set[p] = struct{}{}
		}
	}
	return set, nil
}

func serializePortSet(set map[int]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	var parts []string
	start, prev := ports[0], ports[0]
	for _, p := range ports[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		parts = append(parts, formatPortRange(start, prev))
		start, prev = p, p
	}
	parts = append(parts, formatPortRange(start, prev))
	return strings.Join(parts, ",")
}

func formatPortRange(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}
