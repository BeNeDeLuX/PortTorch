package pipeline

import (
	"context"
	"net"
)

// RunSNMPProbe attempts a small batch of read-only nmap NSE scripts
// (community string "public", the universal SNMP default - not a
// wordlist/brute-force attempt) against UDP/161 on ip, independent of
// whatever TCP ports were discovered for this host. Beyond "snmp-info"
// (basic sysDescr/sysObjectID-level info), "snmp-sysdescr" is a
// second, narrower system-description read, and "snmp-interfaces"/
// "snmp-netstat" enumerate network interfaces and a netstat-like
// connection table respectively - valuable network-topology signal once
// SNMP with a guessable community string is already confirmed present,
// no different in spirit from asking one more question once the door is
// already open.
//
// This is a deliberately narrow, hardcoded exception to an otherwise
// TCP-only pipeline (masscan discovery, RunNmap's -sS/-sV enrichment, and
// every other NSE script in this package all only ever look at TCP ports
// from the requested port spec) - SNMP is UDP-only, so there's no
// TCP-discovered port to key this off of the way ftp-anon/smb-enum-shares
// key off an already-open FTP/SMB port. Rather than adding general UDP
// scanning support (protocol-aware port spec syntax, masscan UDP
// probing, nmap -sU wired through the main enrichment pass), this reuses
// nmap's own SNMP scripts via one small, separate -sU invocation
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
		"--script=snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat",
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

// snmpPortFromNmapRun extracts every SNMP script's result from an
// already-parsed *nmapRun - split out from RunSNMPProbe so the parsing
// logic itself is unit-testable against a hand-built nmapRun, without
// needing a real nmap binary (same reasoning as discoveredFromNmapRun/
// hostResultFromNmapHost in nmap.go). Captures any script with non-empty
// output generically (the same "unrecognized script id -> ExtraScripts"
// treatment nmap.go's per-port default case gives the TCP scripts) rather
// than special-casing "snmp-info" specifically - a host might answer one
// of the four scripts but not another (e.g. a community string that
// permits sysDescr reads but not the fuller interface/netstat tables),
// and any one of them succeeding is equally valid confirmation that SNMP
// is actually present here. Returns nil only when none of them produced
// anything at all.
func snmpPortFromNmapRun(run *nmapRun) *PortResult {
	if len(run.Hosts) == 0 {
		return nil
	}
	for _, p := range run.Hosts[0].Ports.Port {
		var extraScripts []NSEScript
		for _, s := range p.Scripts {
			if s.Output != "" {
				extraScripts = append(extraScripts, NSEScript{ID: s.ID, Output: s.Output})
			}
		}
		if len(extraScripts) == 0 {
			continue
		}
		return &PortResult{
			Port:         161,
			Protocol:     "udp",
			State:        "open",
			ServiceName:  "snmp",
			ExtraScripts: extraScripts,
		}
	}
	return nil
}
