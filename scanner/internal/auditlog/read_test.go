package auditlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadSince(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan-audit.jsonl")

	log, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)
	for _, e := range []Entry{
		{Time: old, ScanJobID: "job-1", IP: "10.0.0.1", Ports: []string{"22/tcp"}, Submitted: true},
		{Time: recent, ScanJobID: "job-2", IP: "10.0.0.2", Ports: []string{"80/tcp", "443/tcp"}, Submitted: true},
		{Time: recent, ScanJobID: "job-2", IP: "10.0.0.3", Ports: []string{"22/tcp"}, Submitted: false},
	} {
		if err := log.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	log.Close()

	all, err := ReadSince(path, time.Time{}, false)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("read %d entries, want 3", len(all))
	}
	if all[0].IP != "10.0.0.1" {
		t.Errorf("entries must come back oldest first, got %s", all[0].IP)
	}

	since, err := ReadSince(path, time.Now().Add(-24*time.Hour), false)
	if err != nil {
		t.Fatalf("ReadSince(since): %v", err)
	}
	if len(since) != 2 {
		t.Errorf("the 48h-old entry should be excluded, got %d entries", len(since))
	}

	// The reason this filter exists: the durable record of what the
	// webserver never received, including entries the retry queue has
	// since given up on and deleted.
	unsub, err := ReadSince(path, time.Time{}, true)
	if err != nil {
		t.Fatalf("ReadSince(unsubmitted): %v", err)
	}
	if len(unsub) != 1 || unsub[0].IP != "10.0.0.3" {
		t.Errorf("unsubmitted filter returned %+v", unsub)
	}
}

// The file is appended to by a live process, so a truncated final line is
// a normal thing to read, not corruption worth refusing the whole history
// over.
func TestReadSinceSkipsUnparseableLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan-audit.jsonl")
	content := `{"time":"2026-09-01T10:00:00Z","ip":"10.0.0.1","ports":["22/tcp"],"submitted":true}
not json at all
{"time":"2026-09-01T11:00:00Z","ip":"10.0.0.2","ports":[],"submitted":true}
{"time":"2026-09-01T12:00:00Z","ip":"10.0.0.3","po`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadSince(path, time.Time{}, false)
	if err != nil {
		t.Fatalf("ReadSince: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("want the 2 complete entries, got %d", len(entries))
	}
}

// A host that has never run a scan has no log, which is an answer rather
// than an error.
func TestReadSinceMissingFile(t *testing.T) {
	entries, err := ReadSince(filepath.Join(t.TempDir(), "nope.jsonl"), time.Time{}, false)
	if err != nil {
		t.Errorf("a missing audit log must not be an error: %v", err)
	}
	if entries != nil {
		t.Errorf("want no entries, got %v", entries)
	}
}
