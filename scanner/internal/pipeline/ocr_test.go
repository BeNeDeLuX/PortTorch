package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunOCRAgainstRealTarget is a real integration test: it screenshots
// the locally running PortTorch webserver's login page (same trick as
// TestGowitnessStageAgainstRealTarget - avoids the unreliable masscan
// self-scan) and OCRs it, checking that the "PortTorch" wordmark on the
// login page is actually recognized. Skipped if gowitness, a
// Chrome/Chromium binary, or tesseract are unavailable.
func TestRunOCRAgainstRealTarget(t *testing.T) {
	if _, err := exec.LookPath("gowitness"); err != nil {
		t.Skip("gowitness not in PATH, skipping integration test")
	}
	if _, err := exec.LookPath("tesseract"); err != nil {
		t.Skip("tesseract not in PATH, skipping integration test")
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
	}.withDefaults()

	shot, err := RunGowitness(context.Background(), cfg, "https://127.0.0.1:443", 443)
	if err != nil {
		t.Fatalf("RunGowitness failed: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(shot.ImagePath))

	text, err := RunOCR(context.Background(), "tesseract", shot.ImagePath)
	if err != nil {
		t.Fatalf("RunOCR failed: %v", err)
	}
	if !strings.Contains(strings.ToLower(text), "porttorch") {
		t.Errorf("expected OCR text to contain %q (the login page wordmark), got: %q", "porttorch", text)
	}
}
