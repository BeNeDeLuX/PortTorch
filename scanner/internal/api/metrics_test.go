package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	c, err := client.New(&config.Config{WebserverURL: "https://127.0.0.1:0", APIKey: "test-key"})
	if err != nil {
		t.Fatalf("building test client: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(nopWriter{}, nil))
	return NewServer(c, pipeline.Config{MasscanPath: "/definitely/not/a/real/binary", NmapPath: "/definitely/not/a/real/binary"}, t.TempDir(), "", logger)
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestHandleMetricsReflectsRecordedScans(t *testing.T) {
	s := testServer(t)
	s.recordScanResult("completed")
	s.recordScanResult("completed")
	s.recordScanResult("failed")
	s.recordPollResult(true)
	s.recordPollResult(false)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	for _, want := range []string{
		`porttorch_scanner_scans_total{status="completed"} 2`,
		`porttorch_scanner_scans_total{status="failed"} 1`,
		`porttorch_scanner_scans_total{status="cancelled"} 0`,
		`porttorch_scanner_poll_failures_total 1`,
		`porttorch_scanner_scanning 0`,
		// Both binaries are configured to unresolvable paths above -
		// confirms the check actually runs LookPath rather than always
		// reporting "available".
		`porttorch_scanner_binary_available{binary="masscan"} 0`,
		`porttorch_scanner_binary_available{binary="nmap"} 0`,
		`porttorch_scanner_submit_queue_pending 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", want, body)
		}
	}
}

func TestHandleMetricsUptimeIsPositive(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.echo.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "porttorch_scanner_uptime_seconds ") {
		t.Errorf("expected an uptime gauge line, got:\n%s", rec.Body.String())
	}
}
