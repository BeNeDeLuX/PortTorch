package pipeline

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
)

// TestRDPScreenshotStageAgainstRealTarget is a real integration test: it
// screenshots a locally running xrdp server (127.0.0.1:3389) through the
// actual startRDPWorkers/hostTracker code path (the same one RunScan uses
// for streaming per-host completion). Skipped if xfreerdp3, Xvfb, or
// import is unavailable.
func TestRDPScreenshotStageAgainstRealTarget(t *testing.T) {
	for _, bin := range []string{"xfreerdp3", "Xvfb", "import"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not in PATH, skipping integration test", bin)
		}
	}

	cfg := Config{
		XfreerdpPath:              "xfreerdp3",
		XvfbPath:                  "Xvfb",
		ImportPath:                "import",
		RDPScreenWidth:            1024,
		RDPScreenHeight:           768,
		RDPConnectTimeoutSeconds:  8,
		RDPScreenshotDelaySeconds: 6,
		Concurrency:               2,
	}.withDefaults()

	host := &HostResult{
		IP: "127.0.0.1",
		Ports: []PortResult{
			{Port: 3389, Protocol: "tcp", State: "open", ServiceName: "ms-wbt-server"},
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

	rdpJobs := make(chan rdpJob, 1)
	var wg sync.WaitGroup
	startRDPWorkers(context.Background(), cfg, rdpJobs, tracker, onProgress, &wg)

	// Only the open port counts as a sub-task - the closed port must
	// never reach the RDP stage at all (RunScan's own nmap loop filters
	// by p.State != "open" before this point).
	tracker.register(host, 1)
	rdpJobs <- rdpJob{ip: host.IP, port: host.Ports[0].Port}
	close(rdpJobs)
	wg.Wait()

	var completed HostResult
	select {
	case completed = <-completedCh:
	default:
		t.Fatal("expected the host to be reported complete after its one sub-task finished")
	}

	if len(completed.RDPScreenshots) != 1 {
		t.Fatalf("expected exactly 1 rdp screenshot, got %d; logs: %v", len(completed.RDPScreenshots), logs)
	}

	shot := completed.RDPScreenshots[0]
	defer CleanupScreenshots([]HostResult{completed})

	if shot.Port != 3389 {
		t.Errorf("expected rdp screenshot port 3389, got %d", shot.Port)
	}
	info, err := os.Stat(shot.ImagePath)
	if err != nil {
		t.Fatalf("expected rdp screenshot image file to exist at %s: %v", shot.ImagePath, err)
	}
	if info.Size() == 0 {
		t.Errorf("expected non-empty rdp screenshot image file")
	}
}

func TestIsRDPPort(t *testing.T) {
	cases := []struct {
		name string
		port PortResult
		want bool
	}{
		{"named ms-wbt-server", PortResult{Port: 4000, ServiceName: "ms-wbt-server"}, true},
		{"named rdp", PortResult{Port: 4000, ServiceName: "rdp"}, true},
		{"unknown on 3389", PortResult{Port: 3389, ServiceName: "unknown"}, true},
		{"unrelated service", PortResult{Port: 3389 + 1, ServiceName: "ssh"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRDPPort(c.port); got != c.want {
				t.Errorf("isRDPPort(%+v) = %v, want %v", c.port, got, c.want)
			}
		})
	}
}
