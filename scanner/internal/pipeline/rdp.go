package pipeline

import (
	"bufio"
	"context"
	"fmt"
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
		"/log-level:OFF",
		"-wallpaper",
		"-decorations",
		// net.JoinHostPort brackets an IPv6 literal - FreeRDP's /v: target
		// documents the same "[ipv6]:port" bracket syntax for this case.
		"/v:" + net.JoinHostPort(ip, strconv.Itoa(port)),
	}
	rdpCmd := exec.CommandContext(ctx, cfg.XfreerdpPath, rdpArgs...)
	rdpCmd.Env = append(os.Environ(), "DISPLAY="+display)
	if err := rdpCmd.Start(); err != nil {
		return nil, fmt.Errorf("starting xfreerdp: %w", err)
	}
	defer stopProcess(rdpCmd)

	select {
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
