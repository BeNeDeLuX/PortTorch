package pipeline

import (
	"context"
	"net"
)

// RunDNSRecursionProbe attempts nmap's "dns-recursion" NSE script against
// UDP/53 on ip, independent of whatever TCP ports were discovered for
// this host - the same kind of deliberately narrow, hardcoded exception
// to the otherwise TCP-only pipeline that RunSNMPProbe/RunIPMIProbe are
// (see snmp.go's doc comment for the full reasoning; it applies
// identically here). "dns-recursion" is documented/exercised by nmap
// itself over UDP (nmap.org's own example is "-sU -p 53
// --script=dns-recursion"), not TCP - even though a DNS server can also
// answer over TCP, the actual security-relevant check here (whether an
// open resolver can be abused as a DNS amplification reflector) only
// means anything over UDP, since that's the transport the abuse itself
// relies on.
//
// An open recursive resolver reachable from arbitrary sources is a real,
// well-known finding - it lets a third party use the target as free
// amplification infrastructure for a DDoS against someone else entirely,
// not just a risk to the resolver's own operator.
//
// Returns (nil, nil) - not an error - when nothing answered or the
// server isn't actually recursive: same "absence means access was
// denied, not a failure" reasoning as RunSNMPProbe/RunIPMIProbe.
func RunDNSRecursionProbe(ctx context.Context, nmap NmapCmd, ip string) (*PortResult, error) {
	args := []string{
		"-Pn", "-R", "--privileged",
		"-sU", "-p", "53",
		"--script=dns-recursion",
		// Same reasoning as RunSNMPProbe/RunIPMIProbe's own
		// --host-timeout: UDP's "no response" is ambiguous, and this
		// runs unconditionally against every scanned host, so one
		// unresponsive host must not stall the whole worker pool.
		"--host-timeout", "10s",
		"-oX", "-",
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		args = append(args, "-6")
	}
	args = append(args, ip)

	run, err := runNmapAndParse(ctx, nmap, args, ip)
	if err != nil {
		return nil, err
	}
	return dnsRecursionPortFromNmapRun(run), nil
}

// dnsRecursionPortFromNmapRun extracts the "dns-recursion" result from an
// already-parsed *nmapRun - split out from RunDNSRecursionProbe so the
// parsing logic itself is unit-testable against a hand-built nmapRun, no
// real nmap binary needed (same reasoning as snmpPortFromNmapRun/
// ipmiPortFromNmapRun).
func dnsRecursionPortFromNmapRun(run *nmapRun) *PortResult {
	if len(run.Hosts) == 0 {
		return nil
	}
	for _, p := range run.Hosts[0].Ports.Port {
		for _, s := range p.Scripts {
			if s.ID == "dns-recursion" && s.Output != "" {
				return &PortResult{
					Port:         53,
					Protocol:     "udp",
					State:        "open",
					ServiceName:  "dns",
					ExtraScripts: []NSEScript{{ID: "dns-recursion", Output: s.Output}},
				}
			}
		}
	}
	return nil
}
