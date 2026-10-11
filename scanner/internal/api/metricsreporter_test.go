package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
)

// Samples that could not be delivered are kept and arrive with the next
// report that succeeds, so a webserver restart leaves no gap in a chart.
func TestMetricsReporterBuffersWhileTheWebserverIsDown(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("needs /proc")
	}
	var mu sync.Mutex
	var batches [][]map[string]any
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/metrics" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		calls++
		var body struct {
			Samples []map[string]any `json:"samples"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// The first two reports fail, as during a webserver restart.
		if calls <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		batches = append(batches, body.Samples)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := client.New(&config.Config{WebserverURL: srv.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(c, pipeline.Config{}, 1, t.TempDir(), "", nil, slog.New(slog.NewTextHandler(nopWriter{}, nil)))
	s.activeScans = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.StartMetricsReporter(ctx, 30*time.Millisecond)

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(batches)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batches) == 0 {
		t.Fatal("no report was ever delivered")
	}
	// The first delivered batch carries the two that failed plus its own.
	if len(batches[0]) != 3 {
		t.Fatalf("first delivered batch has %d samples, want 3", len(batches[0]))
	}
	first := batches[0][0]
	for _, field := range []string{"at", "cpuPercent", "memUsedBytes", "memTotalBytes", "netRxBytesPerSec", "netTxBytesPerSec", "load1"} {
		if _, ok := first[field]; !ok {
			t.Errorf("sample is missing %s: %v", field, first)
		}
	}
	if first["scansRunning"] != float64(2) {
		t.Errorf("scansRunning = %v, want 2", first["scansRunning"])
	}
	if first["memTotalBytes"].(float64) <= 0 {
		t.Error("memTotalBytes should be read from the real /proc/meminfo")
	}
}
