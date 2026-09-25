package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/png"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// isRDPPort decides, based on the service name reported by nmap (with a
// port heuristic as fallback), whether a port is an RDP candidate for the
// screenshot attempt.
func isRDPPort(p PortResult) bool {
	name := strings.ToLower(p.ServiceName)
	if strings.Contains(name, "ms-wbt-server") || strings.Contains(name, "rdp") {
		return true
	}
	return p.Port == 3389
}

// RunRDPScreenshot attempts to screenshot a host's RDP login/connection
// screen. To do so, a virtual X display (Xvfb) is started, xfreerdp
// connects into it with legacy RDP security forced (/sec:rdp, no valid
// credentials), and after a wait period the framebuffer is captured via
// ImageMagick's "import".
//
// Important limitation: if the server enforces Network Level
// Authentication (NLA, often the default on modern Windows versions), the
// connection fails before any graphical output appears - no screenshot is
// possible without valid credentials. This is a property of the RDP
// protocol, not a bug in this function.
func RunRDPScreenshot(ctx context.Context, cfg Config, ip string, port int) (*RDPScreenshot, error) {
	display, xvfbCmd, err := startXvfb(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("starting Xvfb: %w", err)
	}
	defer stopProcess(xvfbCmd)

	rdpArgs := []string{
		"/cert:ignore",
		"/sec:rdp",
		"/u:screenshot",
		"/p:",
		fmt.Sprintf("/w:%d", cfg.RDPScreenWidth),
		fmt.Sprintf("/h:%d", cfg.RDPScreenHeight),
		fmt.Sprintf("/timeout:%d", cfg.RDPConnectTimeoutSeconds*1000),
		// ERROR rather than OFF. OFF silenced the one thing
		// summariseRDPFailure exists to read, so a failed capture arrived
		// with "no output from xfreerdp" as its entire explanation. ERROR
		// still says nothing on a successful capture, so this costs
		// nothing in the normal case.
		"/log-level:ERROR",
		"-wallpaper",
		"-decorations",
		// net.JoinHostPort brackets an IPv6 literal - FreeRDP's /v: target
		// documents the same "[ipv6]:port" bracket syntax for this case.
		"/v:" + net.JoinHostPort(ip, strconv.Itoa(port)),
	}
	rdpCmd := exec.CommandContext(ctx, cfg.XfreerdpPath, rdpArgs...)
	rdpCmd.Env = append(os.Environ(), "DISPLAY="+display)
	// Kept so a failure can say *why* rather than only that it happened -
	// "SEC_E_INVALID_TOKEN" and "connection refused" call for very
	// different responses from whoever reads it.
	var rdpStderr bytes.Buffer
	rdpCmd.Stderr = &rdpStderr
	if err := rdpCmd.Start(); err != nil {
		return nil, fmt.Errorf("starting xfreerdp: %w", err)
	}
	// Waited for in a goroutine rather than left to the deferred kill,
	// because the exit is the signal that matters: xfreerdp that dies
	// immediately - which is what a server requiring NLA does to
	// /sec:rdp - leaves an Xvfb root window nothing ever drew into, and
	// capturing that yields a perfectly valid, perfectly black PNG. The
	// old code only checked that a file appeared and was non-empty, both
	// of which a black frame satisfies, so a refused connection was
	// stored and displayed as though it were a screenshot.
	exited := make(chan error, 1)
	go func() { exited <- rdpCmd.Wait() }()
	defer func() {
		_ = rdpCmd.Process.Kill()
		<-exited
	}()

	select {
	case err := <-exited:
		// Put it back so the deferred drain does not block.
		exited <- err
		return nil, fmt.Errorf(
			"xfreerdp exited before %s:%d could be captured (%v): %s",
			ip, port, err, summariseRDPFailure(rdpStderr.String(), rdpExitCode(err)),
		)
	case <-time.After(time.Duration(cfg.RDPScreenshotDelaySeconds) * time.Second):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	tmpDir, err := os.MkdirTemp("", "rdp-shot-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir for rdp screenshot: %w", err)
	}
	imagePath := filepath.Join(tmpDir, "rdp.png")

	importCmd := exec.CommandContext(ctx, cfg.ImportPath, "-display", display, "-window", "root", imagePath)
	if out, err := importCmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("capturing rdp screenshot for %s:%d: %w (output: %s)", ip, port, err, string(out))
	}

	if info, err := os.Stat(imagePath); err != nil || info.Size() == 0 {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("rdp screenshot for %s:%d was not created", ip, port)
	}

	// Belt and braces alongside the exit check above: xfreerdp can also
	// stay alive having drawn nothing (a server that accepts the
	// connection and then sits silent), and the result is the same black
	// frame. A uniform image is never a real login screen, so it is
	// reported as the failure it is rather than filed as a capture.
	if blank, err := imageIsUniform(imagePath); err == nil && blank {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf(
			"rdp screenshot for %s:%d came out blank - the connection produced no graphical output (a server requiring NLA does this): %s",
			// No exit code to translate here: xfreerdp is still running at
			// this point, so the blankness itself is the whole finding.
			ip, port, summariseRDPFailure(rdpStderr.String(), -1),
		)
	}

	return &RDPScreenshot{Port: port, ImagePath: imagePath}, nil
}

// startXvfb starts Xvfb on an automatically assigned free display (via
// -displayfd, race-free) and returns the display string (e.g. ":123").
func startXvfb(ctx context.Context, cfg Config) (string, *exec.Cmd, error) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return "", nil, fmt.Errorf("creating pipe: %w", err)
	}
	defer readEnd.Close()

	res := fmt.Sprintf("%dx%dx24", cfg.RDPScreenWidth, cfg.RDPScreenHeight)
	cmd := exec.CommandContext(ctx, cfg.XvfbPath, "-displayfd", "3", "-screen", "0", res)
	cmd.ExtraFiles = []*os.File{writeEnd}

	if err := cmd.Start(); err != nil {
		writeEnd.Close()
		return "", nil, err
	}
	writeEnd.Close()

	displayNum, err := readDisplayNumber(readEnd)
	if err != nil {
		stopProcess(cmd)
		return "", nil, err
	}

	return ":" + displayNum, cmd, nil
}

func readDisplayNumber(r *os.File) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading Xvfb display number: %w", err)
		}
		return "", fmt.Errorf("Xvfb did not report a display number")
	}
	num := strings.TrimSpace(scanner.Text())
	if _, err := strconv.Atoi(num); err != nil {
		return "", fmt.Errorf("unexpected Xvfb display output %q: %w", num, err)
	}
	return num, nil
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// imageIsUniform reports whether every pixel of the capture is the same
// colour - the signature of a framebuffer nothing ever drew into.
//
// Deliberately "uniform" rather than "black": Xvfb's empty root is black
// today, but a different depth or a server that paints a solid background
// and nothing else is just as empty of information, and the test costs
// the same.
func imageIsUniform(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		return false, err
	}
	bounds := img.Bounds()
	if bounds.Empty() {
		return true, nil
	}
	first := img.At(bounds.Min.X, bounds.Min.Y)
	fr, fg, fb, fa := first.RGBA()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			if r != fr || g != fg || b != fb || a != fa {
				return false, nil
			}
		}
	}
	return true, nil
}

// summariseRDPFailure turns xfreerdp's output into one line worth putting
// in an error. Its log is verbose and mostly irrelevant; the last
// non-empty line is where the actual reason sits.
// FreeRDP's own exit codes, from client/X11/xfreerdp.h's XF_EXIT_CODE
// enum. Only the ones this pipeline can actually provoke are listed -
// everything about credentials, licensing or logon is unreachable here,
// since the connection is deliberately made without valid credentials and
// never gets that far.
//
// Worth translating because the raw number is genuinely opaque: a real
// report read "exit status 147", which is FreeRDP for "the transport went
// away during connect" and says something quite specific about the
// target. Without this the operator has to go and read FreeRDP's headers
// to learn that.
var rdpExitCodes = map[int]string{
	128: "xfreerdp rejected its own arguments",
	130: "RDP protocol error",
	131: "connection failed",
	133: "security negotiation failed - the server refused the requested security layer",
	136: "pre-connect stage failed",
	138: "post-connect stage failed",
	139: "DNS error",
	140: "DNS name not found",
	141: "connect failed",
	142: "MCS connect-initial error",
	143: "TLS connect failed",
	145: "connect cancelled",
	147: "transport failed during connect - the connection was dropped or reset mid-handshake",
}

func rdpExitCodeMeaning(code int) string {
	if meaning, ok := rdpExitCodes[code]; ok {
		return meaning
	}
	return ""
}

// The most useful line xfreerdp wrote, or - when it wrote nothing - what
// its exit code means.
//
// It frequently writes nothing: the invocation asks for ERROR-level
// logging, and a target that simply drops the connection produces no
// error line at all. "no output from xfreerdp" was then the entire
// explanation a failure came with, which is no explanation. The exit code
// is always there, so it is the floor rather than the last resort.
func summariseRDPFailure(stderr string, exitCode int) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			if len(line) > 200 {
				line = line[:200]
			}
			if meaning := rdpExitCodeMeaning(exitCode); meaning != "" {
				return fmt.Sprintf("%s (%s)", line, meaning)
			}
			return line
		}
	}
	if meaning := rdpExitCodeMeaning(exitCode); meaning != "" {
		return meaning + "; xfreerdp itself logged nothing"
	}
	return "no output from xfreerdp"
}

// The process's exit status, or -1 when it did not exit with one (killed
// by a signal, or never started).
func rdpExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
