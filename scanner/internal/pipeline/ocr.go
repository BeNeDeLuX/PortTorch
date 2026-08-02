package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RunOCR extracts text from a screenshot PNG via Tesseract, so page/login
// content becomes searchable in the dashboard even when it never appears
// in a banner or HTTP header - a login form's static HTML labels, text
// baked into a background image, an RDP login screen's window title.
// "stdout" is Tesseract's own convention for writing recognized text to
// standard output instead of a <outputbase>.txt file.
func RunOCR(ctx context.Context, tesseractPath, imagePath string) (string, error) {
	cmd := exec.CommandContext(ctx, tesseractPath, imagePath, "stdout")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tesseract failed for %s: %w (stderr: %s)", imagePath, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}
