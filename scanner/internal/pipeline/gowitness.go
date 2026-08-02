package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// httpPortHints is used as a fallback if nmap reports a port without a
// clear service name (e.g. "unknown"). 8006 is the Proxmox VE web UI's
// default port - nmap's own service database reports it as
// "wpl-analytics" (a stale/unrelated entry, not an actual identification,
// confirmed against a real host that turned out to be a Proxmox web UI
// with no screenshot or TLS info captured because of exactly this gap),
// so it needs the same port-number fallback as the others here.
var httpPortHints = map[int]bool{
	80: true, 443: true, 8000: true, 8006: true, 8008: true, 8080: true,
	8081: true, 8443: true, 8888: true, 3000: true, 5000: true, 9000: true,
}

// isHTTPPort decides, based on the service name reported by nmap (with a
// port heuristic as fallback), whether a port is an HTTP(S) candidate for
// gowitness, and whether https should be used instead of http.
func isHTTPPort(p PortResult) (isHTTP bool, useTLS bool) {
	name := strings.ToLower(p.ServiceName)
	tunnelSSL := strings.ToLower(p.Tunnel) == "ssl"
	switch {
	case strings.Contains(name, "https"):
		return true, true
	case strings.Contains(name, "ssl"):
		return true, true
	case strings.Contains(name, "http"):
		// nmap sometimes reports the generic "http" service name even
		// when the port is actually TLS-wrapped (its version detection
		// identifies the app-layer protocol post-handshake but doesn't
		// always rename the service to "https") - nmap's own tunnel="ssl"
		// attribute is the reliable signal for that, with the well-known
		// TLS ports as a fallback for when even that isn't set.
		return true, tunnelSSL || p.Port == 443 || p.Port == 8443 || p.Port == 8006
	}
	if httpPortHints[p.Port] {
		return true, p.Port == 443 || p.Port == 8443 || p.Port == 8006
	}
	return false, false
}

type gowitnessTLS struct {
	Protocol    string `json:"protocol"`
	Cipher      string `json:"cipher"`
	SubjectName string `json:"subject_name"`
	Issuer      string `json:"issuer"`
	ValidFrom   string `json:"valid_from"`
	ValidTo     string `json:"valid_to"`
}

type gowitnessTechnology struct {
	Value string `json:"value"`
}

type gowitnessHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type gowitnessResult struct {
	URL          string                `json:"url"`
	ResponseCode int                   `json:"response_code"`
	Title        string                `json:"title"`
	FileName     string                `json:"file_name"`
	Failed       bool                  `json:"failed"`
	FailedReason string                `json:"failed_reason"`
	TLS          *gowitnessTLS         `json:"tls"`
	Technologies []gowitnessTechnology `json:"technologies"`
	Headers      []gowitnessHeader     `json:"headers"`
}

// RunGowitness screenshots a single URL. The screenshot ends up in a new,
// unique temporary directory; the caller must remove its parent directory
// after use (see the Screenshot docs).
func RunGowitness(ctx context.Context, cfg Config, url string, port int) (*Screenshot, error) {
	tmpDir, err := os.MkdirTemp("", "gowitness-shot-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir for gowitness: %w", err)
	}

	jsonlPath := filepath.Join(tmpDir, "result.jsonl")
	args := []string{
		"scan", "single",
		"-u", url,
		"--screenshot-path", tmpDir,
		"--screenshot-format", "png",
		"--write-jsonl", "--write-jsonl-file", jsonlPath,
		"--timeout", strconv.Itoa(cfg.ScreenshotTimeoutSeconds),
		"--chrome-window-x", strconv.Itoa(cfg.ScreenshotWidth),
		"--chrome-window-y", strconv.Itoa(cfg.ScreenshotHeight),
		"-q",
	}
	if cfg.ChromePath != "" {
		args = append(args, "--chrome-path", cfg.ChromePath)
	}

	cmd := exec.CommandContext(ctx, cfg.GowitnessPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("gowitness failed for %s: %w (stdout: %s, stderr: %s)", url, err, stdout.String(), stderr.String())
	}

	result, err := readGowitnessJSONL(jsonlPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("reading gowitness result for %s: %w", url, err)
	}
	if result.Failed {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("gowitness could not screenshot %s: %s", url, result.FailedReason)
	}

	shot := &Screenshot{
		Port:       port,
		URL:        url,
		ImagePath:  filepath.Join(tmpDir, result.FileName),
		HTTPStatus: result.ResponseCode,
		PageTitle:  result.Title,
	}
	if result.TLS != nil {
		shot.TLSProtocol = result.TLS.Protocol
		shot.TLSCipher = result.TLS.Cipher
		shot.TLSSubject = result.TLS.SubjectName
		shot.TLSIssuer = result.TLS.Issuer
		shot.TLSValidFrom = result.TLS.ValidFrom
		shot.TLSValidTo = result.TLS.ValidTo
	}
	for _, t := range result.Technologies {
		if t.Value != "" {
			shot.Technologies = append(shot.Technologies, t.Value)
		}
	}
	if len(result.Headers) > 0 {
		shot.Headers = make(map[string]string, len(result.Headers))
		for _, h := range result.Headers {
			shot.Headers[h.Key] = h.Value
		}
	}

	return shot, nil
}

func readGowitnessJSONL(path string) (*gowitnessResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var result gowitnessResult
		if err := json.Unmarshal(line, &result); err != nil {
			return nil, err
		}
		return &result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// gowitness exits 0 and writes nothing at all (no result line, no
	// error, no non-zero exit code) when the page never finishes loading
	// in a way it can capture - confirmed via manual testing that an HTTP
	// Basic Auth challenge (401 + WWW-Authenticate) reproduces exactly
	// this: Chrome's native, un-dismissable auth prompt blocks the page
	// load, and gowitness silently gives up rather than reporting a
	// failure. It's the single most common real-world cause of this
	// specific "gowitness produced nothing" shape (as opposed to a
	// populated result with failed=true, which covers most other capture
	// failures - see the .Failed check above), so it's worth calling out
	// explicitly here rather than a bare "no result" that gives no hint
	// where to look.
	return nil, fmt.Errorf("gowitness produced no output - most likely the target requires HTTP authentication (e.g. Basic Auth) that presents an un-dismissable browser prompt gowitness can't get past; less commonly a crash or hang gowitness didn't report")
}
