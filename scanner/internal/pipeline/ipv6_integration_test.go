package pipeline

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"
)

// TestRunScanIPv6LoopbackAgainstRealTarget is a real integration test: it
// runs the actual RunScan pipeline against ::1 (IPv6 loopback) with a real
// nmap binary - no masscan involved at all, confirming the whole "IPv6
// target bypasses masscan and uses nmap for both discovery and
// enrichment" path works end to end, not just its individual pieces in
// isolation. Skipped (not failed) if nmap isn't installed or nothing is
// listening on ::1 - e.g. a container without an sshd bound to the IPv6
// loopback - matching this package's existing gated-integration-test
// pattern (see tlscert_test.go/gowitness_test.go).
func TestRunScanIPv6LoopbackAgainstRealTarget(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not in PATH, skipping integration test")
	}
	conn, err := net.DialTimeout("tcp6", "[::1]:22", 2*time.Second)
	if err != nil {
		t.Skip("nothing listening on ::1:22, skipping integration test")
	}
	conn.Close()

	cfg := Config{Concurrency: 2}.withDefaults()

	var completed []HostResult
	result, err := RunScan(
		context.Background(),
		cfg,
		"::1",
		"1-100",
		Excludes{},
		nil,
		func(stage, msg string) { t.Logf("[%s] %s", stage, msg) },
		func(h HostResult) { completed = append(completed, h) },
	)
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	if len(completed) != 1 {
		t.Fatalf("expected exactly one host reported via onHostComplete, got %d: %+v", len(completed), completed)
	}
	host := completed[0]
	if host.IP != "::1" {
		t.Errorf("HostResult.IP = %q, want \"::1\"", host.IP)
	}

	var sshPort *PortResult
	for i := range host.Ports {
		if host.Ports[i].Port == 22 {
			sshPort = &host.Ports[i]
		}
	}
	if sshPort == nil {
		t.Fatalf("expected port 22 to be discovered, got ports: %+v", host.Ports)
	}
	if sshPort.State != "open" {
		t.Errorf("port 22 State = %q, want \"open\"", sshPort.State)
	}
	// ServiceName being populated (not just Port/State) confirms the
	// stage-2 RunNmap enrichment call actually ran with -6 against this
	// IPv6 target - a bare discovery-only result would have this empty.
	if sshPort.ServiceName == "" {
		t.Errorf("expected ServiceName to be populated by the nmap enrichment stage, got empty - discovery may not have been enriched")
	}

	if result.TargetSpec != "::1" || result.PortSpec != "1-100" {
		t.Errorf("unexpected ScanResult target/port spec: %+v", result)
	}
	if len(result.Hosts) != 1 {
		t.Errorf("expected ScanResult.Hosts to also have exactly one entry, got %d", len(result.Hosts))
	}
}
