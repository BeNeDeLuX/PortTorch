package pipeline

import (
	"context"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// The check that separates "captured a login screen" from "captured an
// empty framebuffer" - the whole reason a failed RDP connection used to
// be stored as a screenshot.
func TestImageIsUniform(t *testing.T) {
	write := func(t *testing.T, name string, paint func(*image.RGBA)) string {
		t.Helper()
		img := image.NewRGBA(image.Rect(0, 0, 32, 24))
		paint(img)
		path := filepath.Join(t.TempDir(), name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		defer f.Close()
		if err := png.Encode(f, img); err != nil {
			t.Fatalf("encode: %v", err)
		}
		return path
	}

	black := write(t, "black.png", func(img *image.RGBA) {
		draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{0, 0, 0, 255}}, image.Point{}, draw.Src)
	})
	if uniform, err := imageIsUniform(black); err != nil || !uniform {
		t.Fatalf("an all-black capture must be recognised as blank (uniform=%v err=%v)", uniform, err)
	}

	// Not black, but equally empty of information - which is why the test
	// is for uniformity rather than for the colour black specifically.
	grey := write(t, "grey.png", func(img *image.RGBA) {
		draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{40, 40, 40, 255}}, image.Point{}, draw.Src)
	})
	if uniform, err := imageIsUniform(grey); err != nil || !uniform {
		t.Fatalf("a solid non-black capture must also count as blank (uniform=%v err=%v)", uniform, err)
	}

	// One differing pixel is enough to be a real capture: a login screen
	// is overwhelmingly background, so the test must not need much.
	almost := write(t, "almost.png", func(img *image.RGBA) {
		draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{0, 0, 0, 255}}, image.Point{}, draw.Src)
		img.Set(17, 11, color.RGBA{255, 255, 255, 255})
	})
	if uniform, err := imageIsUniform(almost); err != nil || uniform {
		t.Fatalf("a capture with any content must not be discarded (uniform=%v err=%v)", uniform, err)
	}
}

func TestSummariseRDPFailureTakesTheLastMeaningfulLine(t *testing.T) {
	// xfreerdp's log is verbose and the reason sits at the end.
	got := summariseRDPFailure("[INFO] connecting\n[ERROR] SEC_E_INVALID_TOKEN\n\n", -1)
	if got != "[ERROR] SEC_E_INVALID_TOKEN" {
		t.Fatalf("got %q", got)
	}
	if summariseRDPFailure("   \n\n", -1) != "no output from xfreerdp" {
		t.Fatal("empty output should say so rather than producing a blank reason")
	}
}

// The case a real report arrived as: xfreerdp exits with a code and says
// nothing at all, leaving "no output from xfreerdp" as the entire
// explanation. The exit code is always there, so it is the floor.
func TestSummariseRDPFailureFallsBackToTheExitCode(t *testing.T) {
	got := summariseRDPFailure("", 147)
	if !strings.Contains(got, "transport failed during connect") {
		t.Fatalf("got %q, want the meaning of exit 147", got)
	}
	if !strings.Contains(got, "logged nothing") {
		t.Fatalf("got %q, want it to say xfreerdp itself was silent", got)
	}
}

// When there is both a log line and a code, both are worth having - the
// line says what happened, the code says how FreeRDP classified it.
func TestSummariseRDPFailureCombinesLineAndExitCode(t *testing.T) {
	got := summariseRDPFailure("[ERROR] transport_connect failed", 147)
	if !strings.Contains(got, "transport_connect failed") || !strings.Contains(got, "transport failed during connect") {
		t.Fatalf("got %q, want both the log line and the code's meaning", got)
	}
}

// An unmapped or absent code must not invent a meaning.
func TestSummariseRDPFailureLeavesUnknownCodesAlone(t *testing.T) {
	if got := summariseRDPFailure("", 99); got != "no output from xfreerdp" {
		t.Fatalf("got %q for an unmapped code", got)
	}
	if got := summariseRDPFailure("[ERROR] something", 99); got != "[ERROR] something" {
		t.Fatalf("got %q, want the line unchanged for an unmapped code", got)
	}
}

// Against FreeRDP's own client/X11/xfreerdp.h, so a typo in the table is
// a test failure rather than a plausible-looking wrong explanation.
func TestRDPExitCodeMeaningsMatchFreeRDP(t *testing.T) {
	for code, want := range map[int]string{
		133: "security negotiation",
		143: "TLS connect",
		147: "transport failed",
	} {
		if got := rdpExitCodeMeaning(code); !strings.Contains(got, want) {
			t.Errorf("rdpExitCodeMeaning(%d) = %q, want it to mention %q", code, got, want)
		}
	}
	if rdpExitCodeMeaning(0) != "" {
		t.Error("a successful exit has no failure meaning")
	}
	if rdpExitCodeMeaning(-1) != "" {
		t.Error("no exit status means no meaning to report")
	}
}

func TestRDPExitCodeFromError(t *testing.T) {
	// A process that genuinely exited carries its status; anything else
	// reports -1 rather than a number that looks like one.
	cmd := exec.Command("sh", "-c", "exit 147")
	err := cmd.Run()
	if got := rdpExitCode(err); got != 147 {
		t.Errorf("rdpExitCode = %d, want 147", got)
	}
	if got := rdpExitCode(errors.New("context deadline exceeded")); got != -1 {
		t.Errorf("rdpExitCode = %d, want -1 for a non-exit error", got)
	}
	if got := rdpExitCode(nil); got != -1 {
		t.Errorf("rdpExitCode = %d, want -1 for no error", got)
	}
}
