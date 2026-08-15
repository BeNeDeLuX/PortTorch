package pipeline

import (
	"errors"
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
