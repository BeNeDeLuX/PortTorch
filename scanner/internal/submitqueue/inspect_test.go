package submitqueue

import (
	"testing"

	"porttorch/scanner/internal/pipeline"
)

func TestListAndDiscardPending(t *testing.T) {
	dir := t.TempDir()

	// An empty queue is the common case - most scans never fail a
	// submission - and must not look like a failure.
	if got := ListPending(dir); got != nil {
		t.Errorf("empty queue listed %v", got)
	}
	if n, err := DiscardPending(dir); err != nil || n != 0 {
		t.Errorf("discarding an empty queue = %d, %v", n, err)
	}

	for _, h := range []pipeline.HostResult{
		{IP: "10.0.0.1", Ports: []pipeline.PortResult{
			{Port: 22, Protocol: "tcp", State: "open"},
			{Port: 80, Protocol: "tcp", State: "closed"},
		}},
		{IP: "10.0.0.2", Ports: []pipeline.PortResult{{Port: 443, Protocol: "tcp", State: "open"}}},
	} {
		if err := Enqueue(dir, "job-1", h); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	entries := ListPending(dir)
	if len(entries) != 2 {
		t.Fatalf("listed %d entries, want 2", len(entries))
	}
	byIP := map[string]PendingEntry{}
	for _, e := range entries {
		byIP[e.IP] = e
	}
	// Open ports only, matching what the audit log and the dashboard
	// both count - a closed port is not a finding waiting to be
	// delivered.
	if got := byIP["10.0.0.1"].Ports; got != 1 {
		t.Errorf("10.0.0.1 open ports = %d, want 1 (the closed one doesn't count)", got)
	}
	if byIP["10.0.0.1"].JobID != "job-1" {
		t.Errorf("job id = %q", byIP["10.0.0.1"].JobID)
	}
	if CountPending(dir) != 2 {
		t.Errorf("CountPending disagrees with ListPending")
	}

	n, err := DiscardPending(dir)
	if err != nil {
		t.Fatalf("DiscardPending: %v", err)
	}
	if n != 2 {
		t.Errorf("discarded %d, want 2", n)
	}
	if CountPending(dir) != 0 {
		t.Error("queue should be empty after discarding")
	}
}
