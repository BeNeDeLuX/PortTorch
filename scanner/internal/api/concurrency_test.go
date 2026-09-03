package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
)

// fakeWebserver stands in for the ingest API for the duration of one
// queue-loop test. Every scan it hands out blocks inside GetExcludes -
// the first webserver call runScan makes - until release is closed, which
// is what makes "a scan is currently running" an observable, controllable
// state rather than a race against a real masscan.
type fakeWebserver struct {
	server   *httptest.Server
	claimed  atomic.Int64
	inScan   atomic.Int64
	release  chan struct{}
	pending  atomic.Int64
	releaseO sync.Once
	// Every X-Scanner-Scan-Slots value seen on a queue poll, so a test can
	// assert what the dashboard would have been told.
	slotHeaders atomic.Value
}

func (f *fakeWebserver) slotHeadersSnapshot() []string {
	if v, ok := f.slotHeaders.Load().([]string); ok {
		return v
	}
	return nil
}

func newFakeWebserver(t *testing.T, pending int64) *fakeWebserver {
	t.Helper()
	f := &fakeWebserver{release: make(chan struct{})}
	f.pending.Store(pending)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/ingest/scan-requests/next", func(w http.ResponseWriter, r *http.Request) {
		f.slotHeaders.Store(append(f.slotHeadersSnapshot(), r.Header.Get("X-Scanner-Scan-Slots")))
		if f.pending.Add(-1) < 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		id := f.claimed.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         fmt.Sprintf("req-%d", id),
			"targetSpec": fmt.Sprintf("240.0.0.%d", id),
			"portSpec":   "80",
		})
	})
	mux.HandleFunc("/api/ingest/scan-jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("job-%d", f.claimed.Load())})
	})
	mux.HandleFunc("/api/ingest/excludes", func(w http.ResponseWriter, r *http.Request) {
		f.inScan.Add(1)
		defer f.inScan.Add(-1)
		<-f.release
		// Failing the scan here keeps the test to the queue loop itself:
		// what happens after this point (masscan, nmap, submission) is
		// covered by the pipeline's own tests.
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(func() {
		f.releaseAll()
		f.server.Close()
	})
	return f
}

func (f *fakeWebserver) releaseAll() {
	f.releaseO.Do(func() { close(f.release) })
}

func serverWithLimit(t *testing.T, f *fakeWebserver, maxConcurrent int) *Server {
	t.Helper()
	c, err := client.New(&config.Config{WebserverURL: f.server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(nopWriter{}, nil))
	return NewServer(c, pipeline.Config{
		MasscanPath: "/definitely/not/a/real/binary",
		NmapPath:    "/definitely/not/a/real/binary",
	}, maxConcurrent, t.TempDir(), "", nil, logger)
}

// drainPolls does what StartPolling's ticker branch does: keep claiming
// until the slots are full or the queue is empty.
func drainPolls(s *Server) int {
	claimed := 0
	for s.pollOnce(context.Background()) {
		claimed++
	}
	return claimed
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The behaviour that existed before maxConcurrentScans: one scan at a
// time, and a second queued request simply waits.
func TestQueueLoopClaimsOneScanAtATimeByDefault(t *testing.T) {
	f := newFakeWebserver(t, 5)
	s := serverWithLimit(t, f, 1)

	if got := drainPolls(s); got != 1 {
		t.Fatalf("expected exactly 1 claim with a limit of 1, got %d", got)
	}
	waitFor(t, "the scan to start", func() bool { return f.inScan.Load() == 1 })

	// A second tick while that scan is still running must not claim
	// anything - claiming would mark the request as this scanner's on the
	// webserver while it sat there unworked.
	if got := drainPolls(s); got != 0 {
		t.Fatalf("expected no further claims while a scan is running, got %d", got)
	}
	if got := f.claimed.Load(); got != 1 {
		t.Fatalf("expected 1 request claimed from the webserver, got %d", got)
	}
}

func TestQueueLoopRunsUpToTheConfiguredLimitInParallel(t *testing.T) {
	f := newFakeWebserver(t, 5)
	s := serverWithLimit(t, f, 3)

	if got := drainPolls(s); got != 3 {
		t.Fatalf("expected 3 claims with a limit of 3, got %d", got)
	}
	waitFor(t, "all three scans to start", func() bool { return f.inScan.Load() == 3 })

	if got := drainPolls(s); got != 0 {
		t.Fatalf("expected the loop to stop once every slot is busy, got %d more claims", got)
	}
	if got := f.claimed.Load(); got != 3 {
		t.Fatalf("expected 3 requests claimed from the webserver, got %d", got)
	}
}

func TestSlotsAreReleasedWhenAScanFinishes(t *testing.T) {
	f := newFakeWebserver(t, 5)
	s := serverWithLimit(t, f, 2)

	if got := drainPolls(s); got != 2 {
		t.Fatalf("expected 2 claims, got %d", got)
	}
	waitFor(t, "both scans to start", func() bool { return f.inScan.Load() == 2 })

	f.releaseAll()
	waitFor(t, "the slots to be freed", func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.runningScans == 0
	})

	// Freed slots must be reusable - a leaked slot would leave the
	// scanner permanently unable to pick up work, which is exactly the
	// failure mode a counter kept separately from len(cancels) can
	// introduce. How many claims each drain gets is timing-dependent now
	// that the released scans fail immediately, so what's asserted is the
	// outcome: the remaining three queued requests all get picked up.
	claimedAfterRelease := 0
	waitFor(t, "the rest of the queue to be picked up", func() bool {
		claimedAfterRelease += drainPolls(s)
		return f.claimed.Load() == 5
	})
	if claimedAfterRelease == 0 {
		t.Fatal("expected the freed slots to be reused, but nothing was claimed")
	}
}

// An empty queue must still cost exactly one poll per tick, not one per
// free slot - otherwise raising the limit would multiply the request rate
// against the webserver for a scanner with nothing to do.
func TestAnEmptyQueueCostsOnePollPerTick(t *testing.T) {
	f := newFakeWebserver(t, 0)
	s := serverWithLimit(t, f, 4)

	if got := drainPolls(s); got != 0 {
		t.Fatalf("expected no claims from an empty queue, got %d", got)
	}
	if got := f.pending.Load(); got != -1 {
		t.Fatalf("expected exactly 1 poll against the webserver, got %d", -got)
	}

	// The poll itself reserves a slot before asking, so this header used
	// to report the scanner as busy for the entire time it had nothing to
	// do - the dashboard showed an idle scanner at 1/4.
	for _, header := range f.slotHeadersSnapshot() {
		if header != "" && !strings.HasPrefix(header, "0/") {
			t.Fatalf("an idle poll reported busy slots: %q", header)
		}
	}
}

func TestRestTriggeredScanOccupiesASlot(t *testing.T) {
	f := newFakeWebserver(t, 5)
	s := serverWithLimit(t, f, 1)

	// Stands in for handleCreateScan's own reservation: an operator's
	// local scan is never refused, but the queue loop must back off while
	// it runs rather than piling a second scan on top of it.
	s.reserveScanSlot()
	defer s.releaseScanSlot()

	if got := drainPolls(s); got != 0 {
		t.Fatalf("expected the queue loop to back off, got %d claims", got)
	}
}

func TestApplyServeOverrides(t *testing.T) {
	maxScans := 1
	if value, changed := applyServeOverrides(&maxScans, 1, map[string]int{"maxConcurrentScans": 4}); value != 4 || !changed {
		t.Fatalf("expected the override to apply, got value=%d changed=%v", value, changed)
	}
	// Re-applying the same override is not a change (so it doesn't log).
	if _, changed := applyServeOverrides(&maxScans, 1, map[string]int{"maxConcurrentScans": 4}); changed {
		t.Fatal("expected re-applying the same override to report no change")
	}
	// Clearing it restores config.yaml's own value rather than leaving
	// the last pushed one in place - the whole point of base-first.
	if value, changed := applyServeOverrides(&maxScans, 1, map[string]int{}); value != 1 || !changed {
		t.Fatalf("expected clearing to restore the base value, got value=%d changed=%v", value, changed)
	}
	// A nonsensical value is ignored rather than stalling the scanner.
	if value, _ := applyServeOverrides(&maxScans, 2, map[string]int{"maxConcurrentScans": 0}); value != 2 {
		t.Fatalf("expected 0 to be ignored, got %d", value)
	}
}

// baseConfigValues is what the dashboard's Configure dialog shows as "your
// config.yaml says this", so it has to report the file's own values - not
// the effective ones, which already have any dashboard override folded in.
// Reporting the effective config would make an override look like the
// file's value, leaving nothing to clear back to.
func TestBaseConfigValuesReportTheFileNotTheOverride(t *testing.T) {
	f := newFakeWebserver(t, 0)
	c, err := client.New(&config.Config{WebserverURL: f.server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(nopWriter{}, nil))
	s := NewServer(c, pipeline.Config{
		MasscanRate:              1000,
		MasscanRetries:           2,
		Concurrency:              5,
		GowitnessConcurrency:     2,
		ScreenshotTimeoutSeconds: 20,
		RDPConcurrency:           2,
		NucleiConcurrency:        2,
		NucleiTimeoutSeconds:     10,
		TLSCertTimeoutSeconds:    8,
	}, 1, t.TempDir(), "", nil, logger)

	before := s.baseConfigValues()
	if before["masscanRate"] != 1000 || before["concurrency"] != 5 || before["maxConcurrentScans"] != 1 {
		t.Fatalf("unexpected base values: %+v", before)
	}

	// Apply overrides the way the config watcher does.
	s.cfgMu.Lock()
	applyConfigOverrides(&s.pcfg, s.baseCfg, map[string]int{"masscanRate": 50, "concurrency": 16})
	applyServeOverrides(&s.maxScans, s.baseMaxScans, map[string]int{"maxConcurrentScans": 4})
	s.cfgMu.Unlock()

	// The running config really did change...
	if got := s.pipelineConfig().MasscanRate; got != 50 {
		t.Fatalf("expected the override to apply to the running config, got %d", got)
	}
	if got := s.maxConcurrentScans(); got != 4 {
		t.Fatalf("expected the serve override to apply, got %d", got)
	}
	// ...but what gets reported is still the file's own values.
	after := s.baseConfigValues()
	if after["masscanRate"] != 1000 || after["concurrency"] != 5 || after["maxConcurrentScans"] != 1 {
		t.Errorf("base values changed with the override: %+v", after)
	}
}

// Reported once per process, since config.yaml can't change without a
// restart - but a webserver that was unreachable at startup must not leave
// the dashboard permanently showing shipped defaults.
func TestBaseConfigIsReportedOnceAndRetriedOnFailure(t *testing.T) {
	var reports atomic.Int64
	var fail atomic.Bool
	fail.Store(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ingest/config-report" {
			reports.Add(1)
			if fail.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	c, err := client.New(&config.Config{WebserverURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(nopWriter{}, nil))
	s := NewServer(c, pipeline.Config{MasscanRate: 1000}, 1, t.TempDir(), "", nil, logger)

	s.reportBaseConfigOnce(context.Background())
	if reports.Load() != 1 {
		t.Fatalf("expected 1 attempt, got %d", reports.Load())
	}
	// Failed, so it must try again rather than giving up silently.
	s.reportBaseConfigOnce(context.Background())
	if reports.Load() != 2 {
		t.Fatalf("expected a retry after failure, got %d attempts", reports.Load())
	}

	fail.Store(false)
	s.reportBaseConfigOnce(context.Background())
	if reports.Load() != 3 {
		t.Fatalf("expected the successful attempt, got %d", reports.Load())
	}
	// Now it must stop: re-sending an unchangeable value every tick is noise.
	s.reportBaseConfigOnce(context.Background())
	s.reportBaseConfigOnce(context.Background())
	if reports.Load() != 3 {
		t.Errorf("expected no further attempts after success, got %d", reports.Load())
	}
}
