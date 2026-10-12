package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixedUDPProbeInScope(t *testing.T) {
	cases := []struct {
		spec string
		port int
		want bool
	}{
		{"22", 161, false},     // the reported case: SSH only
		{"1-10000", 161, true}, // a plain range covers the probe ports
		{"1-10000", 53, true},
		{"1-1024", 1900, false},
		{"22,161", 161, true},
		{"22,U:161", 161, true}, // an explicit UDP request
		{"U:100-200", 161, true},
		{"T:1-10000", 161, false}, // explicitly TCP only
		{"T:22,U:53", 53, true},
		{"T:22,U:53", 161, false},
		{"80, 443 ,161", 161, true},
		{"", 161, false},
	}
	for _, c := range cases {
		if got := fixedUDPProbeInScope(c.spec, c.port); got != c.want {
			t.Errorf("fixedUDPProbeInScope(%q, %d) = %v, want %v", c.spec, c.port, got, c.want)
		}
	}
}

// With U:161 in the spec, nmap may already have reported 161/udp - the
// probe's scripts join that entry instead of adding a second one.
func TestAddProbePortMergesIntoAnExistingEntry(t *testing.T) {
	h := &HostResult{Ports: []PortResult{
		{Port: 161, Protocol: "udp", State: "open", ExtraScripts: []NSEScript{{ID: "snmp-info", Output: "a"}}},
	}}
	addProbePort(h, PortResult{Port: 161, Protocol: "udp", State: "open", ServiceName: "snmp", ExtraScripts: []NSEScript{
		{ID: "snmp-info", Output: "b"}, {ID: "snmp-interfaces", Output: "c"},
	}})
	if len(h.Ports) != 1 {
		t.Fatalf("got %d entries for 161/udp, want 1", len(h.Ports))
	}
	if got := len(h.Ports[0].ExtraScripts); got != 2 || h.Ports[0].ServiceName != "snmp" {
		t.Errorf("merged entry = %+v, want snmp-info once plus snmp-interfaces and the service name", h.Ports[0])
	}
	addProbePort(h, PortResult{Port: 623, Protocol: "udp", State: "open"})
	if len(h.Ports) != 2 {
		t.Errorf("a different port must be appended, got %d entries", len(h.Ports))
	}
}

// The real RunScan against stand-ins, logging every nmap invocation: which
// fixed UDP probes actually go out for a given port spec.
func TestRunScanSendsOnlyTheUDPProbesInScope(t *testing.T) {
	masscan, _, _ := writeFakeScanners(t, 0)
	dir := t.TempDir()
	nmap := filepath.Join(dir, "nmap")
	logPath := filepath.Join(dir, "nmap.log")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
for a; do last=$a; done
case " $* " in *" -sV "*) ;; *) printf '<?xml version="1.0"?><nmaprun></nmaprun>'; exit 0;; esac
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>' "$last"
`
	if err := os.WriteFile(nmap, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	probed := func(spec string) map[string]bool {
		_ = os.Remove(logPath)
		cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 100000, Concurrency: 2}
		onProgress, onHost, _ := collectingCallbacks()
		if _, err := RunScan(context.Background(), cfg, "10.9.0.0/24", spec, Excludes{}, nil, nil, nil, onProgress, onHost, nil); err != nil {
			t.Fatalf("RunScan(%q): %v", spec, err)
		}
		raw, _ := os.ReadFile(logPath)
		out := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "-sU") || strings.Contains(line, "-sV") {
				continue
			}
			for _, p := range []string{"53", "161", "623", "1900"} {
				if strings.Contains(line, "-p "+p+" ") {
					out[p] = true
				}
			}
		}
		return out
	}

	if got := probed("22"); len(got) != 0 {
		t.Errorf("a scan of 22 sent UDP probes %v, want none", got)
	}
	if got := probed("1-10000"); len(got) != 4 {
		t.Errorf("a scan of 1-10000 sent UDP probes %v, want all four", got)
	}
	if got := probed("22,U:161"); len(got) != 1 || !got["161"] {
		t.Errorf("a scan of 22,U:161 sent UDP probes %v, want only 161", got)
	}
	if got := probed("T:1-10000"); len(got) != 0 {
		t.Errorf("an explicitly TCP-only scan sent UDP probes %v, want none", got)
	}
}
