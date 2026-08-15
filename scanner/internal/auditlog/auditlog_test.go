package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"porttorch/scanner/internal/pipeline"
)

func TestOpenWriteCloseRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "scan-audit.jsonl")

	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	host := pipeline.HostResult{
		IP:       "10.0.0.5",
		Hostname: "web01",
		Ports: []pipeline.PortResult{
			{Port: 443, Protocol: "tcp", State: "open"},
			{Port: 80, Protocol: "tcp", State: "closed"}, // must be filtered out
			{Port: 161, Protocol: "udp", State: "open"},
		},
	}
	if err := a.Write(EntryFromHost("job-1", host, true)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a.Write(EntryFromHost("job-1", pipeline.HostResult{IP: "10.0.0.6"}, false)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopening audit log: %v", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("unmarshaling line %q: %v", scanner.Text(), err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 lines, got %d: %+v", len(entries), entries)
	}

	if entries[0].IP != "10.0.0.5" || entries[0].Hostname != "web01" || !entries[0].Submitted {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if len(entries[0].Ports) != 2 || entries[0].Ports[0] != "443/tcp" || entries[0].Ports[1] != "161/udp" {
		t.Errorf("expected only the two open ports in port/protocol form, got %v", entries[0].Ports)
	}

	if entries[1].IP != "10.0.0.6" || entries[1].Submitted {
		t.Errorf("unexpected second entry: %+v", entries[1])
	}
}

// Confirms this file is genuinely append-only across separate Open calls
// - a scanner restarting between scans (or "scan"/"menu" running many
// times) must never lose or overwrite what a prior process already wrote.
func TestOpenAppendsAcrossSeparateOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-audit.jsonl")

	a1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := a1.Write(EntryFromHost("job-1", pipeline.HostResult{IP: "10.0.0.1"}, true)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if err := a2.Write(EntryFromHost("job-2", pipeline.HostResult{IP: "10.0.0.2"}, true)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := a2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lineCount := 0
	for _, b := range data {
		if b == '\n' {
			lineCount++
		}
	}
	if lineCount != 2 {
		t.Errorf("expected 2 lines across both opens, got %d in:\n%s", lineCount, data)
	}
}

// Concurrent writers (the pipeline submits multiple hosts' results in
// parallel as they stream in) must never interleave partial JSON lines.
func TestWriteIsSafeForConcurrentUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-audit.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := pipeline.HostResult{IP: "10.0.0.1", Ports: []pipeline.PortResult{{Port: 22, Protocol: "tcp", State: "open"}}}
			_ = a.Write(EntryFromHost("job-concurrent", host, true))
		}(i)
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not valid JSON (%v): %q", count, err, scanner.Text())
		}
		count++
	}
	if count != n {
		t.Errorf("expected %d valid lines, got %d", n, count)
	}
}

func TestNilAuditLogIsANoOp(t *testing.T) {
	var a *AuditLog
	if err := a.Write(Entry{IP: "10.0.0.1"}); err != nil {
		t.Errorf("expected a nil *AuditLog's Write to be a no-op, got %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("expected a nil *AuditLog's Close to be a no-op, got %v", err)
	}
}
