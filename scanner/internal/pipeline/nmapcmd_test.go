package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNmapCmdCommandShape(t *testing.T) {
	ctx := context.Background()

	direct := NmapCmd{Path: "/usr/bin/nmap"}.command(ctx, "-Pn", "-p", "22", "10.0.0.1")
	if direct.Path == "" || !strings.HasSuffix(direct.Path, "nmap") {
		t.Fatalf("direct invocation should run nmap itself, got %q", direct.Path)
	}
	// Byte-identical to what this built before NmapCmd existed - a scanner
	// with sudo off must produce exactly the command line it always did.
	wantDirect := []string{"/usr/bin/nmap", "-Pn", "-p", "22", "10.0.0.1"}
	if got := direct.Args; !equalStrings(got, wantDirect) {
		t.Errorf("direct args = %v, want %v", got, wantDirect)
	}

	sudo := NmapCmd{Path: "/usr/local/bin/porttorch-nmap", Sudo: true}.command(ctx, "-Pn", "-O", "10.0.0.1")
	wantSudo := []string{"sudo", "-n", "/usr/local/bin/porttorch-nmap", "-Pn", "-O", "10.0.0.1"}
	if got := sudo.Args; !equalStrings(got, wantSudo) {
		t.Errorf("sudo args = %v, want %v", got, wantSudo)
	}
}

func TestNmapCmdElevated(t *testing.T) {
	if !(NmapCmd{Sudo: true}).elevated() {
		t.Error("a sudo invocation must count as elevated - it is the whole point of the wrapper")
	}
	// Without sudo this depends on the euid the test happens to run as,
	// which is exactly what the production check does too.
	if got, want := (NmapCmd{}).elevated(), os.Geteuid() == 0; got != want {
		t.Errorf("non-sudo elevated() = %v, want %v (euid %d)", got, want, os.Geteuid())
	}
}

func TestConfigNmapCmd(t *testing.T) {
	got := Config{NmapPath: "/x/nmap", NmapSudo: true}.nmapCmd()
	if got.Path != "/x/nmap" || !got.Sudo {
		t.Errorf("nmapCmd() = %+v, want the config's own path and sudo flag", got)
	}
	if (Config{NmapPath: "nmap"}).nmapCmd().Sudo {
		t.Error("sudo must default to off, so an existing config keeps behaving as before")
	}
}

// The wrapper is the actual security boundary for running nmap as root
// (see porttorch-nmap's own header), so it is tested as the shell script
// it is, against a stand-in for nmap - not reasoned about. Every "allow"
// case below is a real argument list built by this package.
func TestNmapWrapperArgumentAllowlist(t *testing.T) {
	wrapper, err := filepath.Abs("../../porttorch-nmap")
	if err != nil {
		t.Fatalf("resolving wrapper path: %v", err)
	}
	if _, err := os.Stat(wrapper); err != nil {
		t.Skipf("wrapper not present: %v", err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash not available: %v", err)
	}

	dir := t.TempDir()
	fakeNmap := filepath.Join(dir, "nmap")
	if err := os.WriteFile(fakeNmap, []byte("#!/bin/sh\necho FAKE \"$@\"\n"), 0o755); err != nil {
		t.Fatalf("writing fake nmap: %v", err)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.Command(bash, append([]string{wrapper}, args...)...)
		cmd.Env = append(os.Environ(), "PORTTORCH_NMAP_BIN="+fakeNmap)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	allowed := map[string][]string{
		"tcp enrichment":  {"-Pn", "-R", "--privileged", "-sV", "--script=banner,ssh-hostkey", "-O", "-p", "22,443", "-oX", "-", "10.0.0.5"},
		"udp and tcp":     {"-Pn", "-R", "--privileged", "-sV", "--script=banner", "-sU", "-sS", "-O", "-p", "T:80,U:53", "-oX", "-", "10.0.0.5"},
		"ipv6 enrichment": {"-Pn", "-R", "--privileged", "-sV", "--script=banner", "-O", "-6", "-p", "443", "-oX", "-", "2001:db8::1"},
		"ipv6 discovery":  {"-6", "-Pn", "--privileged", "-sS", "-p", "1-1000", "-oX", "-", "2001:db8::1", "2001:db8::2"},
		"snmp probe":      {"-Pn", "-R", "--privileged", "-sU", "-p", "161", "--script=snmp-info,snmp-sysdescr", "--host-timeout", "10s", "-oX", "-", "10.0.0.5"},
		"script wildcard": {"-Pn", "--privileged", "--script=http-*", "-p", "80", "-oX", "-", "10.0.0.5"},
	}
	for name, args := range allowed {
		if out, err := run(args...); err != nil {
			t.Errorf("%s: wrapper rejected a real pipeline invocation: %v\n%s", name, err, out)
		} else if !strings.HasPrefix(out, "FAKE ") {
			t.Errorf("%s: wrapper did not reach nmap, got %q", name, out)
		}
	}

	rejected := map[string][]string{
		"script from a path": {"-Pn", "--script=/tmp/evil.nse", "-p", "80", "-oX", "-", "10.0.0.5"},
		"script directory":   {"-Pn", "--script=.", "-p", "80", "-oX", "-", "10.0.0.5"},
		"script-args":        {"-Pn", "--script=banner", "--script-args=x=1", "-p", "80", "-oX", "-", "10.0.0.5"},
		"xml output to file": {"-Pn", "-oX", "/etc/cron.d/x", "-p", "80", "10.0.0.5"},
		"other output flag":  {"-Pn", "-oN", "/root/out", "-p", "80", "10.0.0.5"},
		"custom datadir":     {"-Pn", "--datadir", "/tmp/evil", "-p", "80", "-oX", "-", "10.0.0.5"},
		"targets from file":  {"-Pn", "-iL", "/etc/shadow", "-p", "80", "-oX", "-", "10.0.0.5"},
		"hostname target":    {"-Pn", "-p", "80", "-oX", "-", "evil.example.com"},
		"no target at all":   {"-Pn", "-p", "80", "-oX", "-"},
		"unknown flag":       {"-Pn", "--resume", "/tmp/x", "-p", "80", "-oX", "-", "10.0.0.5"},
	}
	for name, args := range rejected {
		out, err := run(args...)
		if err == nil {
			t.Errorf("%s: wrapper allowed an argument it must refuse\n%s", name, out)
			continue
		}
		if !strings.Contains(out, "refusing to run") {
			t.Errorf("%s: rejected without saying why: %q", name, out)
		}
		if strings.Contains(out, "FAKE ") {
			t.Errorf("%s: rejected but still reached nmap: %q", name, out)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNmapEnrichArgsPrivilegeDependentFlags(t *testing.T) {
	base := func(elevated bool) []string {
		return nmapEnrichArgs("22,443", "10.0.0.5", []string{"banner"}, false, true, elevated, false)
	}

	if got := strings.Join(base(false), " "); strings.Contains(got, "-O") {
		t.Errorf("unprivileged run must not ask for -O (nmap refuses to start at all): %s", got)
	}
	if got := strings.Join(base(true), " "); !strings.Contains(got, "-O") {
		t.Errorf("elevated run must ask for -O, or OS detection silently never happens: %s", got)
	}

	// The unprivileged command line has to stay exactly what it was before
	// any of this existed, since that is what every scanner without the
	// sudo wrapper keeps running.
	want := []string{"-Pn", "-R", "--privileged", "-sV", "--script=banner", "-p", "22,443", "-oX", "-", "10.0.0.5"}
	if got := base(false); !equalStrings(got, want) {
		t.Errorf("unprivileged args = %v, want %v", got, want)
	}

	udp := nmapEnrichArgs("T:80,U:53", "10.0.0.5", nil, true, true, true, false)
	joined := strings.Join(udp, " ")
	for _, flag := range []string{"-sU", "-sS", "-O"} {
		if !strings.Contains(joined, flag) {
			t.Errorf("mixed UDP/TCP elevated run is missing %s: %s", flag, joined)
		}
	}
	if v6 := nmapEnrichArgs("443", "2001:db8::1", nil, false, true, false, true); !strings.Contains(strings.Join(v6, " "), "-6") {
		t.Errorf("IPv6 target must get -6: %v", v6)
	}
}
