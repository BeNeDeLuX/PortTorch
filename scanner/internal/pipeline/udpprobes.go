package pipeline

import (
	"strconv"
	"strings"
)

// The four fixed UDP probes (DNS recursion on 53, SNMP on 161, IPMI on 623,
// UPnP on 1900) used to run against every host of every scan, whatever the
// port spec said. A scan of "22" therefore still sent SNMP, IPMI, DNS and
// SSDP packets to every host it found - traffic the operator had not asked
// for, against a scope chosen precisely to keep a scan narrow.
//
// A probe now runs only when its port number is in the requested spec:
//
//   - a bare part counts ("1-10000" covers 161), because nobody typing a
//     plain range thinks of these probes as a separate protocol choice, and
//     before this they ran for exactly those scans anyway;
//   - a "U:" part counts, being an explicit request for that UDP port;
//   - a "T:" part does not, since it explicitly asks for TCP only.
//
// Callers pass the spec as requested, not the one left after port
// excludes: subtracting excludes normalises a TCP-only spec and drops its
// "T:" prefixes, which would turn "T:1-10000" back into a plain range.
// Excludes are still honoured - isPortExcludedForHost checks them for each
// of these ports separately.
func fixedUDPProbeInScope(portSpec string, port int) bool {
	for _, part := range strings.Split(portSpec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(part) > 2 && part[1] == ':' {
			if part[0] == 'T' || part[0] == 't' {
				continue
			}
			part = part[2:]
		}
		lo, hi := part, part
		if before, after, ok := strings.Cut(part, "-"); ok {
			lo, hi = before, after
		}
		l, errLo := strconv.Atoi(strings.TrimSpace(lo))
		h, errHi := strconv.Atoi(strings.TrimSpace(hi))
		if errLo == nil && errHi == nil && l <= port && port <= h {
			return true
		}
	}
	return false
}

// Adds a fixed UDP probe's result to the host. With "U:161" in the spec,
// discovery and nmap may already have reported 161/udp, so the probe's
// scripts are merged into that entry rather than producing a second row
// for the same port.
func addProbePort(h *HostResult, port PortResult) {
	for i := range h.Ports {
		existing := &h.Ports[i]
		if existing.Port != port.Port || existing.Protocol != port.Protocol {
			continue
		}
		have := map[string]bool{}
		for _, s := range existing.ExtraScripts {
			have[s.ID] = true
		}
		for _, s := range port.ExtraScripts {
			if !have[s.ID] {
				existing.ExtraScripts = append(existing.ExtraScripts, s)
			}
		}
		if existing.ServiceName == "" {
			existing.ServiceName = port.ServiceName
		}
		return
	}
	h.Ports = append(h.Ports, port)
}
