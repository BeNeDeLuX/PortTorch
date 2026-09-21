package pipeline

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestRecoverJobCatchesPanicAndCallsOnPanic(t *testing.T) {
	var recovered any
	didPanic := true

	func() {
		defer func() {
			// recoverJob itself must not let the panic escape - if it
			// did, this deferred recover would still catch it, but the
			// test should fail loudly rather than silently pass.
			if r := recover(); r != nil {
				t.Fatalf("panic escaped recoverJob: %v", r)
			}
		}()
		recoverJob(func(r any) {
			recovered = r
			didPanic = false // reached only if onPanic actually ran
		}, func() {
			panic("boom")
		})
	}()

	if didPanic {
		t.Fatal("onPanic was never called")
	}
	if recovered != "boom" {
		t.Errorf("recovered value = %v, want %q", recovered, "boom")
	}
}

func TestRecoverJobRunsOnPanicOnlyOnActualPanic(t *testing.T) {
	onPanicCalled := false
	ran := false

	recoverJob(func(r any) {
		onPanicCalled = true
	}, func() {
		ran = true
	})

	if !ran {
		t.Error("fn was never called")
	}
	if onPanicCalled {
		t.Error("onPanic was called even though fn didn't panic")
	}
}

// Simulates the exact pattern every worker pool in this file uses: a host
// is registered with the tracker before its sub-tasks are dispatched, and
// a sub-task that panics still reaches tracker.complete via onPanic (see
// e.g. startSNMPWorkers) - confirming the host still eventually fires
// onHostComplete exactly once, just without that one sub-task's
// contribution, rather than hanging forever (remaining count stuck above
// zero) or firing twice.
func TestRecoverJobStillCompletesHostTrackerOnPanic(t *testing.T) {
	var completedHosts []HostResult
	tracker := newHostTracker(func(h HostResult) {
		completedHosts = append(completedHosts, h)
	})

	host := &HostResult{IP: "10.0.0.5"}
	tracker.register(host, 2) // two sub-tasks expected

	// First sub-task succeeds normally.
	recoverJob(func(r any) {
		t.Fatalf("unexpected panic in first sub-task: %v", r)
	}, func() {
		tracker.complete("10.0.0.5", func(h *HostResult) {
			h.Ports = append(h.Ports, PortResult{Port: 22, Protocol: "tcp", State: "open"})
		})
	})

	// Second sub-task panics - same shape as every start*Workers function
	// in this file: onPanic reports it and calls tracker.complete(ip, nil).
	recoverJob(func(r any) {
		tracker.complete("10.0.0.5", nil)
	}, func() {
		panic("simulated probe crash")
	})

	if len(completedHosts) != 1 {
		t.Fatalf("expected onHostComplete to fire exactly once, fired %d times", len(completedHosts))
	}
	if completedHosts[0].IP != "10.0.0.5" {
		t.Errorf("unexpected completed host: %+v", completedHosts[0])
	}
	if len(completedHosts[0].Ports) != 1 || completedHosts[0].Ports[0].Port != 22 {
		t.Errorf("expected only the successful sub-task's port, got %+v", completedHosts[0].Ports)
	}
}

func TestIsTimeoutLikeErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"gowitness deadline exceeded", errors.New("gowitness could not screenshot http://x:80: context deadline exceeded"), true},
		{"generic timeout wording", errors.New("dial tcp 10.0.0.1:443: i/o timeout"), true},
		{"uppercase Timeout", errors.New("Timeout waiting for response"), true},
		// Deterministic failures that would just fail again identically -
		// retrying these would waste time, not improve success rate.
		{"connection refused", errors.New("dial tcp 10.0.0.1:3389: connect: connection refused"), false},
		{"nla rejection", errors.New("rdp screenshot for 10.0.0.1:3389 was not created"), false},
		{"binary not found", errors.New("starting xfreerdp: exec: \"xfreerdp3\": executable file not found in $PATH"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTimeoutLikeErr(c.err); got != c.want {
				t.Errorf("isTimeoutLikeErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestIsHostname(t *testing.T) {
	cases := []struct {
		name       string
		targetSpec string
		want       bool
	}{
		{"single IPv4", "10.0.0.1", false},
		{"CIDR", "10.0.0.0/24", false},
		{"IPv4 range", "10.0.0.1-10.0.0.10", false},
		{"comma-separated multi-target", "10.0.0.1,10.0.0.2", false},
		{"plain hostname", "example.com", true},
		{"hostname with a hyphen", "web-01.internal.example.com", true},
		{"bare short hostname (no dots)", "my-scanner-target", true},
		{"empty string", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isHostname(c.targetSpec); got != c.want {
				t.Errorf("isHostname(%q) = %v, want %v", c.targetSpec, got, c.want)
			}
		})
	}
}

// TestResolveHostnameIPv4RealDNS is a real integration test - it performs
// an actual DNS lookup for "localhost", not a mock, to confirm
// resolveHostnameIPv4's use of net.DefaultResolver actually works end to
// end rather than just type-checking. "localhost" resolves to 127.0.0.1 on
// every real environment this is expected to run in (no network access
// needed - it's satisfied locally via /etc/hosts or the OS's own stub
// resolver).
func TestResolveHostnameIPv4RealDNS(t *testing.T) {
	ip, err := resolveHostnameIPv4(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("resolveHostnameIPv4(localhost) failed: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("resolveHostnameIPv4(localhost) = %q, want 127.0.0.1", ip)
	}
}

func TestResolveHostnameIPv4UnresolvableFailsClearly(t *testing.T) {
	_, err := resolveHostnameIPv4(context.Background(), "this-hostname-should-never-resolve.invalid")
	if err == nil {
		t.Fatal("expected an error resolving a nonexistent hostname, got nil")
	}
}

func TestWithProbeHostname(t *testing.T) {
	original := map[string]string{"10.0.0.5": "existing.internal"}

	merged := withProbeHostname(original, "10.0.0.9", "new.internal")

	if len(original) != 1 {
		t.Errorf("withProbeHostname mutated the caller's original map - got %d entries, want 1", len(original))
	}
	if merged["10.0.0.5"] != "existing.internal" {
		t.Errorf("merged map lost the original entry: %v", merged)
	}
	if merged["10.0.0.9"] != "new.internal" {
		t.Errorf("merged map missing the new entry: %v", merged)
	}

	// A nil input map must not panic and should still produce a working
	// single-entry map - the case every caller that's never configured any
	// probe hostnames hits.
	fromNil := withProbeHostname(nil, "10.0.0.1", "only.internal")
	if len(fromNil) != 1 || fromNil["10.0.0.1"] != "only.internal" {
		t.Errorf("withProbeHostname(nil, ...) = %v, want a single entry", fromNil)
	}
}

// A target spec may mix names with IPs, CIDRs and ranges. The guarantee
// that matters most is the negative one: a spec with no names in it comes
// back byte-identical, so nothing that works today changes shape on its
// way to masscan.
func TestResolveHostnamesInTargetSpecLeavesNonHostnameSpecsUntouched(t *testing.T) {
	unchanged := []string{
		"10.0.0.5",
		"10.0.0.0/24",
		"10.0.0.1-10.0.0.50",
		"10.0.0.0/24,192.168.1.0/24",
		"2001:db8::1",
		// A comma-separated IPv6 list - the case the comma rule in
		// isHostname was originally written to protect.
		"2001:db8::1,2001:db8::2",
		"10.0.0.1, 10.0.0.2",
		"",
	}
	for _, spec := range unchanged {
		t.Run(spec, func(t *testing.T) {
			got, resolved, err := resolveHostnamesInTargetSpec(context.Background(), spec, noopProgress)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != spec {
				t.Fatalf("spec was rewritten: got %q, want %q unchanged", got, spec)
			}
			if len(resolved) != 0 {
				t.Fatalf("nothing should have been resolved, got %v", resolved)
			}
		})
	}
}

// localhost is the one name every machine running these tests resolves,
// so it stands in for a real hostname without needing a fixture resolver.
func TestResolveHostnamesInTargetSpecResolvesSeveralAndMixes(t *testing.T) {
	if _, err := resolveHostnameIPv4(context.Background(), "localhost"); err != nil {
		t.Skipf("localhost does not resolve to IPv4 here: %v", err)
	}

	spec := "localhost,10.0.0.0/24,localhost"
	got, resolved, err := resolveHostnamesInTargetSpec(context.Background(), spec, noopProgress)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parts := strings.Split(got, ",")
	if len(parts) != 3 {
		t.Fatalf("part count changed: got %q", got)
	}
	if net.ParseIP(parts[0]) == nil || net.ParseIP(parts[2]) == nil {
		t.Fatalf("both names should have become addresses: %q", got)
	}
	// The untouched part keeps its exact position, so the order someone
	// typed is the order masscan receives.
	if parts[1] != "10.0.0.0/24" {
		t.Fatalf("the CIDR moved or changed: %q", got)
	}
	if len(resolved) != 1 {
		// Both names are the same host, so one address is recorded once.
		t.Fatalf("expected one resolved address, got %v", resolved)
	}
	for ip, hostname := range resolved {
		if hostname != "localhost" {
			t.Fatalf("resolved map should name the hostname, got %q for %s", hostname, ip)
		}
	}
}

// Fail-closed: one unresolvable name stops the scan rather than silently
// scanning a subset of what was asked for.
func TestResolveHostnamesInTargetSpecFailsOnOneBadName(t *testing.T) {
	spec := "10.0.0.1,no-such-host.invalid"
	_, _, err := resolveHostnamesInTargetSpec(context.Background(), spec, noopProgress)
	if err == nil {
		t.Fatal("expected an error rather than a partial target list")
	}
	if !strings.Contains(err.Error(), "no-such-host.invalid") {
		t.Fatalf("the error should name the host that failed, got: %v", err)
	}
}
