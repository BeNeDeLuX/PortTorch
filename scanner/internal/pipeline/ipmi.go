package pipeline

import (
	"context"
	"net"
)

// RunIPMIProbe attempts nmap's "ipmi-version" NSE script against UDP/623
// on ip, independent of whatever TCP ports were discovered for this host -
// the same kind of deliberately narrow, hardcoded exception to the
// otherwise TCP-only pipeline that RunSNMPProbe is (see snmp.go's doc
// comment for the full reasoning; it applies identically here). IPMI/BMC
// out-of-band management interfaces are a classic high-risk target
// (frequently left on defaults, exposed to a network segment that
// shouldn't reach them at all) that would otherwise never surface in this
// scanner's entirely-TCP pipeline.
//
// Returns (nil, nil) - not an error - when nothing answered: same
// "absence means access was denied, not a failure" reasoning as
// RunSNMPProbe.
func RunIPMIProbe(ctx context.Context, binPath, ip string) (*PortResult, error) {
	args := []string{
		"-Pn", "-R", "--privileged",
		"-sU", "-p", "623",
		"--script=ipmi-version",
		// Same reasoning as RunSNMPProbe's own --host-timeout: UDP's "no
		// response" is ambiguous, and this runs unconditionally against
		// every scanned host, so one unresponsive host must not stall
		// the whole IPMI worker pool.
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
	return ipmiPortFromNmapRun(run), nil
}

// ipmiPortFromNmapRun extracts the "ipmi-version" result from an already-
// parsed *nmapRun - split out from RunIPMIProbe so the parsing logic
// itself is unit-testable against a hand-built nmapRun, without needing a
// real nmap binary (same reasoning as snmpPortFromNmapRun).
func ipmiPortFromNmapRun(run *nmapRun) *PortResult {
	if len(run.Hosts) == 0 {
		return nil
	}
	for _, p := range run.Hosts[0].Ports.Port {
		for _, s := range p.Scripts {
			if s.ID == "ipmi-version" && s.Output != "" {
				return &PortResult{
					Port:         623,
					Protocol:     "udp",
					State:        "open",
					ServiceName:  "ipmi",
					ExtraScripts: []NSEScript{{ID: "ipmi-version", Output: s.Output}},
				}
			}
		}
	}
	return nil
}
