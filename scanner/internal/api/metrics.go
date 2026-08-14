package api

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// handleMetrics exposes a small set of fleet-monitoring signals in
// Prometheus's plain-text exposition format, so a scanner's health can be
// watched independently of the webserver's own last-seen-based heuristics
// (see CLAUDE.md's "Active scans and scanner agent versions" - those are
// necessarily inferred from the outside, this is the scanner reporting on
// itself directly). Deliberately hand-written rather than pulling in
// prometheus/client_golang: the exposition format itself is simple plain
// text, and this is a handful of gauges/counters already tracked
// elsewhere in this package (scanState, s.cancels, submitqueue) - a
// dependency would buy encoding/registry machinery this doesn't need.
func (s *Server) handleMetrics(c echo.Context) error {
	var b strings.Builder

	writeGauge(&b, "porttorch_scanner_uptime_seconds", "Seconds since this scanner process started.", time.Since(s.started).Seconds())

	scanning := 0.0
	if s.IsScanning() {
		scanning = 1
	}
	writeGauge(&b, "porttorch_scanner_scanning", "Whether a scan is currently in progress (1) or not (0).", scanning)

	s.metricsMu.Lock()
	scansTotal := make(map[string]int, len(s.scansTotal))
	for status, count := range s.scansTotal {
		scansTotal[status] = count
	}
	pollsFailed := s.pollsFailed
	lastPollOK := s.lastPollOK
	lastPollFail := s.lastPollFail
	s.metricsMu.Unlock()

	fmt.Fprintf(&b, "# HELP porttorch_scanner_scans_total Total scans completed, by terminal status.\n# TYPE porttorch_scanner_scans_total counter\n")
	for _, status := range []string{"completed", "failed", "cancelled"} {
		fmt.Fprintf(&b, "porttorch_scanner_scans_total{status=%q} %d\n", status, scansTotal[status])
	}

	writeCounter(&b, "porttorch_scanner_poll_failures_total", "Total failed polls to the webserver's scan-request queue.", float64(pollsFailed))
	if !lastPollOK.IsZero() {
		writeGauge(&b, "porttorch_scanner_last_poll_success_timestamp_seconds", "Unix timestamp of the last successful poll.", float64(lastPollOK.Unix()))
	}
	if !lastPollFail.IsZero() {
		writeGauge(&b, "porttorch_scanner_last_poll_failure_timestamp_seconds", "Unix timestamp of the last failed poll.", float64(lastPollFail.Unix()))
	}

	pending := 0
	if entries, err := os.ReadDir(s.queueDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				pending++
			}
		}
	}
	writeGauge(&b, "porttorch_scanner_submit_queue_pending", "Host submissions currently queued for retry (see internal/submitqueue).", float64(pending))

	fmt.Fprintf(&b, "# HELP porttorch_scanner_binary_available Whether a required external binary is resolvable on PATH (1) or not (0).\n# TYPE porttorch_scanner_binary_available gauge\n")
	for _, bin := range []struct{ label, path string }{
		{"masscan", s.pcfg.MasscanPath},
		{"nmap", s.pcfg.NmapPath},
	} {
		available := 0.0
		if _, err := exec.LookPath(bin.path); err == nil {
			available = 1
		}
		fmt.Fprintf(&b, "porttorch_scanner_binary_available{binary=%q} %g\n", bin.label, available)
	}

	return c.String(200, b.String())
}

func writeGauge(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}

func writeCounter(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %g\n", name, help, name, name, value)
}
