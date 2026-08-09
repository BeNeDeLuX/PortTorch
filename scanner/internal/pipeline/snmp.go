package pipeline

import (
	"context"
	"net"
)

// RunSNMPProbe attempts nmap's "snmp-info" NSE script (community string
// "public", the universal SNMP default - not a wordlist/brute-force
// attempt) against UDP/161 on ip, independent of whatever TCP ports were
// discovered for this host.
//
// This is a deliberately narrow, hardcoded exception to an otherwise
// TCP-only pipeline (masscan discovery, RunNmap's -sS/-sV enrichment, and
// every other NSE script in this package all only ever look at TCP ports
// from the requested port spec) - SNMP is UDP-only, so there's no
// TCP-discovered port to key this off of the way ftp-anon/smb-enum-shares
// key off an already-open FTP/SMB port. Rather than adding general UDP
// scanning support (protocol-aware port spec syntax, masscan UDP
// probing, nmap -sU wired through the main enrichment pass), this reuses
// nmap's own "snmp-info" script via one small, separate -sU invocation
// scoped to exactly this one well-known port - the smallest change that
// makes SNMP asset info available at all, without touching the TCP-only
// contract everything else in this package relies on.
//
// Returns (nil, nil) - not an error - when nothing answered (no SNMP
// service, or one that doesn't accept the "public" community string):
// same "absence means access was denied, not a failure" reasoning as
// ftp-anon/smb-enum-shares, so callers never fabricate a port row for a
// service that was never actually confirmed present.
func RunSNMPProbe(ctx context.Context, binPath, ip string) (*PortResult, error) {
	args := []string{
		"-Pn", "-R", "--privileged",
		"-sU", "-p", "161",
		"--script=snmp-info",
		// UDP's "no response" is inherently ambiguous (closed vs filtered
		// vs just slow), and this now runs unconditionally against every
		// scanned host (see orchestrator.go) - a bounded host-timeout
		// keeps one unresponsive host from stalling the whole SNMP worker
		// pool rather than inheriting nmap's own, much more patient UDP
		// defaults.
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
	return snmpPortFromNmapRun(run), nil
}

// snmpPortFromNmapRun extracts the "snmp-info" result from an already-
// parsed *nmapRun - split out from RunSNMPProbe so the parsing logic
// itself is unit-testable against a hand-built nmapRun, without needing a
// real nmap binary (same reasoning as discoveredFromNmapRun/
// hostResultFromNmapHost in nmap.go).
func snmpPortFromNmapRun(run *nmapRun) *PortResult {
	if len(run.Hosts) == 0 {
		return nil
	}
	for _, p := range run.Hosts[0].Ports.Port {
		for _, s := range p.Scripts {
			if s.ID == "snmp-info" && s.Output != "" {
				return &PortResult{
					Port:         161,
					Protocol:     "udp",
					State:        "open",
					ServiceName:  "snmp",
					ExtraScripts: []NSEScript{{ID: "snmp-info", Output: s.Output}},
				}
			}
		}
	}
	return nil
}
