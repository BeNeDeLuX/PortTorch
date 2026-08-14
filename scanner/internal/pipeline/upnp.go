package pipeline

import (
	"context"
	"net"
)

// RunUPnPProbe attempts nmap's "upnp-info" NSE script against UDP/1900 on
// ip (the well-known SSDP/UPnP discovery port), independent of whatever
// TCP ports were discovered for this host - the same kind of deliberately
// narrow, hardcoded exception to the otherwise TCP-only pipeline that
// RunSNMPProbe/RunIPMIProbe/RunDNSRecursionProbe are (see snmp.go's doc
// comment for the full reasoning; it applies identically here).
// "upnp-info" is nmap's own "safe"+"discovery"-categorized script
// (confirmed against a real local nmap install's script.db, not assumed -
// this codebase has a real precedent, documented in CLAUDE.md, for a
// wrong category assumption breaking every host in a scan) - it just asks
// a UPnP root device to describe itself, the same read a router/NAS/smart-
// TV's own control point would make. A UPnP responder reachable from
// beyond its intended local segment is a real, common misconfiguration
// (UPnP was never designed to be exposed past a single LAN) worth
// surfacing the same way an open SNMP/IPMI service already is.
//
// Deliberately excludes "ntp-monlist" (UDP/123, the classic NTP
// amplification-vector check) from this same treatment - confirmed
// against nmap's own script.db that it's categorized "intrusive", not
// "safe", unlike every other script in this narrow-exception UDP probe
// group. Running an intrusive script unconditionally against every scanned
// host would be a real change to this scanner's safe-by-default posture,
// not a mechanical addition like this one - so it's left out rather than
// silently included.
//
// Returns (nil, nil) - not an error - when nothing answered: same
// "absence means access was denied, not a failure" reasoning as
// RunSNMPProbe.
func RunUPnPProbe(ctx context.Context, binPath, ip string) (*PortResult, error) {
	args := []string{
		"-Pn", "-R", "--privileged",
		"-sU", "-p", "1900",
		"--script=upnp-info",
		// Same reasoning as RunSNMPProbe's own --host-timeout: UDP's "no
		// response" is ambiguous, and this runs unconditionally against
		// every scanned host, so one unresponsive host must not stall
		// the whole UPnP worker pool.
		"--host-timeout", "10s",
		"-oX", "-",
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		args = append(args, "-6")
	}
	args = append(args, ip)

	run, err := runNmapAndParse(ctx, binPath, args, ip)
	if err != nil {
		return nil, err
	}
	return upnpPortFromNmapRun(run), nil
}

// upnpPortFromNmapRun extracts the "upnp-info" result from an already-
// parsed *nmapRun - split out from RunUPnPProbe so the parsing logic
// itself is unit-testable against a hand-built nmapRun, without needing a
// real nmap binary (same reasoning as snmpPortFromNmapRun).
func upnpPortFromNmapRun(run *nmapRun) *PortResult {
	if len(run.Hosts) == 0 {
		return nil
	}
	for _, p := range run.Hosts[0].Ports.Port {
		for _, s := range p.Scripts {
			if s.ID == "upnp-info" && s.Output != "" {
				return &PortResult{
					Port:         1900,
					Protocol:     "udp",
					State:        "open",
					ServiceName:  "upnp",
					ExtraScripts: []NSEScript{{ID: "upnp-info", Output: s.Output}},
				}
			}
		}
	}
	return nil
}
