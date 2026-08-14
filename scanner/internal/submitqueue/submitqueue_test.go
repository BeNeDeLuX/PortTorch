package submitqueue

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
)

func testClient(t *testing.T, handler http.HandlerFunc) *client.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	c, err := client.New(&config.Config{WebserverURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	return c
}

func testHost(t *testing.T, withScreenshot bool) pipeline.HostResult {
	t.Helper()
	host := pipeline.HostResult{IP: "10.0.0.5", Ports: []pipeline.PortResult{{Port: 443, Protocol: "tcp", State: "open"}}}
	if withScreenshot {
		dir := t.TempDir()
		imgPath := filepath.Join(dir, "screenshot.png")
		if err := os.WriteFile(imgPath, []byte("fake-png-bytes"), 0o644); err != nil {
			t.Fatalf("writing fake screenshot: %v", err)
		}
		host.Screenshots = []pipeline.Screenshot{{Port: 443, URL: "https://10.0.0.5/", ImagePath: imgPath}}
	}
	return host
}

// A submission the webserver always accepts should be enqueued, then
// removed from disk on the very first Drain call - the common,
// short-lived-outage case this whole package exists for.
func TestEnqueueThenDrainSucceeds(t *testing.T) {
	var hostsCalls, imageCalls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ingest/hosts":
			atomic.AddInt32(&hostsCalls, 1)
		case "/api/ingest/screenshots":
			atomic.AddInt32(&imageCalls, 1)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	queueDir := t.TempDir()
	host := testHost(t, true)
	originalImagePath := host.Screenshots[0].ImagePath

	if err := Enqueue(queueDir, "job-1", host); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// The original image file must be untouched (still readable at its
	// original path) - Enqueue must copy, not move/mutate, since every
	// caller still runs pipeline.CleanupScreenshots against the
	// original host value right after this.
	if _, err := os.Stat(originalImagePath); err != nil {
		t.Errorf("original screenshot file should still exist: %v", err)
	}

	entries, err := os.ReadDir(queueDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one queued entry, got %v (err %v)", entries, err)
	}

	result := Drain(context.Background(), queueDir, c)
	if result.Succeeded != 1 || result.GaveUp != 0 || result.Pending != 0 {
		t.Fatalf("unexpected drain result: %+v", result)
	}
	if hostsCalls != 1 {
		t.Errorf("expected exactly one /hosts call, got %d", hostsCalls)
	}
	if imageCalls != 1 {
		t.Errorf("expected exactly one screenshot upload, got %d", imageCalls)
	}

	remaining, _ := os.ReadDir(queueDir)
	if len(remaining) != 0 {
		t.Errorf("expected the queue entry to be removed after a successful drain, got %v", remaining)
	}
}

// A submission the webserver keeps rejecting must not be retried forever
// - after maxAttempts failed Drain calls, the entry is dropped rather
// than accumulating on disk indefinitely.
func TestDrainGivesUpAfterMaxAttempts(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	queueDir := t.TempDir()
	if err := Enqueue(queueDir, "job-1", testHost(t, false)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	var last DrainResult
	for i := 0; i < maxAttempts; i++ {
		last = Drain(context.Background(), queueDir, c)
		entries, _ := os.ReadDir(queueDir)
		if i < maxAttempts-1 {
			if last.Pending != 1 || len(entries) != 1 {
				t.Fatalf("attempt %d: expected the entry to remain pending, got result %+v, %d entries on disk", i+1, last, len(entries))
			}
		}
	}

	if last.GaveUp != 1 {
		t.Fatalf("expected the final attempt to give up, got %+v", last)
	}
	remaining, _ := os.ReadDir(queueDir)
	if len(remaining) != 0 {
		t.Errorf("expected the queue entry to be removed after giving up, got %v", remaining)
	}
}

// Drain against a directory that doesn't exist at all (no submission has
// ever failed) must be a silent no-op, not an error - this is the normal
// state for the overwhelming majority of scans.
func TestDrainEmptyOrMissingQueueDir(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("webserver should never be contacted when the queue is empty")
	})

	result := Drain(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), c)
	if !result.Empty() {
		t.Errorf("expected an empty result, got %+v", result)
	}
}
