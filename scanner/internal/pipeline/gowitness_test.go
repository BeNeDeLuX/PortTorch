package pipeline

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
)

// TestGowitnessStageAgainstRealTarget is a real integration test: it
// screenshots the locally running PortTorch webserver (https://localhost:443)
// through the actual startGowitnessWorkers/hostTracker code path (the same
// one RunScan uses for streaming per-host completion), without needing
// the unreliable masscan self-scan. Skipped if gowitness or a
// Chrome/Chromium binary is unavailable.
func TestGowitnessStageAgainstRealTarget(t *testing.T) {
	if _, err := exec.LookPath("gowitness"); err != nil {
		t.Skip("gowitness not in PATH, skipping integration test")
	}
	chromePath := ""
	for _, candidate := range []string{"chromium", "google-chrome", "chromium-browser"} {
		if p, err := exec.LookPath(candidate); err == nil {
			chromePath = p
			break
		}
	}
	if chromePath == "" {
		t.Skip("no Chrome/Chromium found, skipping integration test")
	}

	cfg := Config{
		GowitnessPath:            "gowitness",
		ChromePath:               chromePath,
		ScreenshotTimeoutSeconds: 20,
		Concurrency:              2,
	}.withDefaults()

	host := &HostResult{
		IP: "127.0.0.1",
		Ports: []PortResult{
			{Port: 443, Protocol: "tcp", State: "open", ServiceName: "https"},
			{Port: 9, Protocol: "tcp", State: "closed", ServiceName: "discard"},
		},
	}

	var logsMu sync.Mutex
	var logs []string
	onProgress := func(stage, message string) {
		logsMu.Lock()
		logs = append(logs, stage+": "+message)
		logsMu.Unlock()
	}

	completedCh := make(chan HostResult, 1)
	tracker := newHostTracker(func(h HostResult) { completedCh <- h })

	shotJobs := make(chan shotJob, 1)
	var wg sync.WaitGroup
	startGowitnessWorkers(context.Background(), cfg, shotJobs, tracker, onProgress, &wg)

	// Only the open, https-classified port counts as a sub-task - the
	// closed port must never reach the gowitness stage at all (RunScan's
	// own nmap loop is what filters by p.State != "open" before this
	// point, so this test drives the worker pool the same way it would
	// really be driven).
	tracker.register(host, 1)
	shotJobs <- shotJob{ip: host.IP, port: host.Ports[0], useTLS: true}
	close(shotJobs)
	wg.Wait()

	var completed HostResult
	select {
	case completed = <-completedCh:
	default:
		t.Fatal("expected the host to be reported complete after its one sub-task finished")
	}

	if len(completed.Screenshots) != 1 {
		t.Fatalf("expected exactly 1 screenshot, got %d; logs: %v", len(completed.Screenshots), logs)
	}

	shot := completed.Screenshots[0]
	defer CleanupScreenshots([]HostResult{completed})

	if shot.Port != 443 {
		t.Errorf("expected screenshot port 443, got %d", shot.Port)
	}
	if shot.HTTPStatus == 0 {
		t.Errorf("expected a non-zero HTTP status")
	}
	if shot.PageTitle == "" {
		t.Errorf("expected a non-empty page title")
	}
	info, err := os.Stat(shot.ImagePath)
	if err != nil {
		t.Fatalf("expected screenshot image file to exist at %s: %v", shot.ImagePath, err)
	}
	if info.Size() == 0 {
		t.Errorf("expected non-empty screenshot image file")
	}
}

func TestIsHTTPPort(t *testing.T) {
	cases := []struct {
		name     string
		port     PortResult
		wantHTTP bool
		wantTLS  bool
	}{
		{"named http", PortResult{Port: 8000, ServiceName: "http"}, true, false},
		{"named https", PortResult{Port: 8000, ServiceName: "https"}, true, true},
		{"named ssl", PortResult{Port: 8000, ServiceName: "ssl"}, true, true},
		{"unknown on 443", PortResult{Port: 443, ServiceName: "unknown"}, true, true},
		{"unknown on 80", PortResult{Port: 80, ServiceName: "unknown"}, true, false},
		{"unrelated service", PortResult{Port: 22, ServiceName: "ssh"}, false, false},
		// Regression: nmap's own service database labels 8006 as
		// "wpl-analytics" - not an actual identification, just a stale/
		// unrelated entry - but it's the Proxmox VE web UI's default
		// (HTTPS) port, and a real host running exactly this got no
		// screenshot or TLS info because of that misleading name.
		{"proxmox web ui on 8006 with unhelpful service name", PortResult{Port: 8006, ServiceName: "wpl-analytics"}, true, true},
		// Regression: nmap can report the generic "http" service name for
		// a TLS-wrapped service on a well-known TLS port instead of
		// renaming it to "https" - this bit a real scan (port 443 showing
		// up as plain "http", no certificate captured anywhere).
		{"named http on 443", PortResult{Port: 443, ServiceName: "http"}, true, true},
		{"named http on 8443", PortResult{Port: 8443, ServiceName: "http"}, true, true},
		{"named http on 80", PortResult{Port: 80, ServiceName: "http"}, true, false},
		// nmap's own tunnel="ssl" attribute should win even on a
		// non-standard port with a generic "http" service name.
		{"named http with ssl tunnel on non-standard port", PortResult{Port: 8080, ServiceName: "http", Tunnel: "ssl"}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isHTTP, useTLS := isHTTPPort(c.port)
			if isHTTP != c.wantHTTP || useTLS != c.wantTLS {
				t.Errorf("isHTTPPort(%+v) = (%v, %v), want (%v, %v)", c.port, isHTTP, useTLS, c.wantHTTP, c.wantTLS)
			}
		})
	}
}
