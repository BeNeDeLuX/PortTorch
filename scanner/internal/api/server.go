package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/progress"
)

// Server is the scanner's REST API, through which scans can be triggered
// remotely. Uses the same orchestrator as the TUI and the "scan" CLI
// subcommand.
type Server struct {
	echo   *echo.Echo
	client *client.Client
	pcfg   pipeline.Config
	token  string
	logger *slog.Logger

	mu      sync.RWMutex
	scans   map[string]*scanState
	cancels map[string]context.CancelFunc
}

// NewServer builds the Echo app including routes. If token is non-empty,
// all requests must send an "Authorization: Bearer <token>" header. logger
// should be a JSON logger (see internal/logging) so that all stdout output
// of "serve" mode remains consistently machine-readable.
func NewServer(c *client.Client, pcfg pipeline.Config, token string, logger *slog.Logger) *Server {
	s := &Server{
		echo:    echo.New(),
		client:  c,
		pcfg:    pcfg,
		token:   token,
		logger:  logger,
		scans:   make(map[string]*scanState),
		cancels: make(map[string]context.CancelFunc),
	}
	s.echo.HideBanner = true
	s.echo.HidePort = true
	s.echo.Use(middleware.Recover())
	s.echo.Use(s.accessLogMiddleware)
	if token != "" {
		s.echo.Use(s.authMiddleware)
	}

	s.echo.GET("/healthz", s.handleHealth)
	s.echo.POST("/scans", s.handleCreateScan)
	s.echo.GET("/scans/:id", s.handleGetScan)

	return s
}

// Start blocks and listens on addr.
func (s *Server) Start(addr string) error {
	return s.echo.Start(addr)
}

// accessLogMiddleware logs every request in structured form instead of
// Echo's default text format, so stdout consistently consists of JSON
// lines.
func (s *Server) accessLogMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		s.logger.Info("http request",
			"event", "http.request",
			"method", c.Request().Method,
			"path", c.Path(),
			"status", c.Response().Status,
			"duration_ms", time.Since(start).Milliseconds(),
			"source_ip", c.RealIP(),
		)
		return err
	}
}

func (s *Server) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			s.logger.Warn("scanner api request without bearer token", "event", "auth.token_missing", "source_ip", c.RealIP())
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or missing bearer token"})
		}
		provided := strings.TrimPrefix(header, prefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			s.logger.Warn("scanner api request with invalid token", "event", "auth.token_invalid", "source_ip", c.RealIP())
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or missing bearer token"})
		}
		return next(c)
	}
}

func (s *Server) handleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

type createScanRequest struct {
	Target string `json:"target"`
	Ports  string `json:"ports"`
}

func (s *Server) handleCreateScan(c echo.Context) error {
	var req createScanRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Ports = strings.TrimSpace(req.Ports)
	if req.Target == "" || req.Ports == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "target and ports are required"})
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), timeoutCreateJob)
	defer cancel()
	// Cancellable: this scan runs inside the long-lived "serve" process,
	// which also runs StartCancelWatcher.
	jobID, err := s.client.CreateScanJob(ctx, req.Target, req.Ports, true)
	if err != nil {
		return c.JSON(http.StatusBadGateway, map[string]string{"error": "creating scan job failed: " + err.Error()})
	}

	state := newScanState(req.Target, req.Ports)
	s.mu.Lock()
	s.scans[jobID] = state
	s.mu.Unlock()

	s.logger.Info("scan requested via rest api", "event", "scan.requested", "scan_job_id", jobID, "target", req.Target, "ports", req.Ports, "source_ip", c.RealIP())
	go s.runScan(jobID, req.Target, req.Ports, state)

	return c.JSON(http.StatusAccepted, map[string]string{"id": jobID, "status": "running"})
}

func (s *Server) handleGetScan(c echo.Context) error {
	id := c.Param("id")
	s.mu.RLock()
	state, ok := s.scans[id]
	s.mu.RUnlock()
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "scan not found"})
	}
	snapshot := state.snapshot()
	return c.JSON(http.StatusOK, snapshot)
}

// StartPolling periodically asks the webserver for pending scan requests
// (rescan button, schedules) and runs them through the same path as
// POST /scans. Blocks until ctx is done - typically started as its own
// goroutine alongside s.Start().
func (s *Server) StartPolling(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pollOnce(ctx)
		}
	}
}

// StartCancelWatcher periodically checks whether an operator has
// requested that any currently-running, cancellable scan stop, and if so
// cancels its context - this has to run as a separate goroutine/loop from
// StartPolling, since that loop blocks for the entire duration of a
// queue-triggered scan (inside s.runScan) and couldn't notice anything
// else in the meantime. Blocks until ctx is done - typically started
// alongside s.Start() and StartPolling().
func (s *Server) StartCancelWatcher(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkCancellations(ctx)
		}
	}
}

func (s *Server) checkCancellations(ctx context.Context) {
	s.mu.RLock()
	jobIDs := make([]string, 0, len(s.cancels))
	for id := range s.cancels {
		jobIDs = append(jobIDs, id)
	}
	s.mu.RUnlock()

	for _, jobID := range jobIDs {
		checkCtx, cancel := context.WithTimeout(ctx, timeoutCreateJob)
		requested, err := s.client.CheckCancelRequested(checkCtx, jobID)
		cancel()
		if err != nil {
			s.logger.Error("checking scan cancellation status failed", "event", "cancel_watch.failed", "scan_job_id", jobID, "error", err.Error())
			continue
		}
		if !requested {
			continue
		}
		s.mu.RLock()
		cancelFunc, ok := s.cancels[jobID]
		s.mu.RUnlock()
		if ok {
			cancelFunc()
		}
	}
}

func (s *Server) pollOnce(ctx context.Context) {
	pollCtx, cancel := context.WithTimeout(ctx, timeoutCreateJob)
	scanReq, err := s.client.PollNextScanRequest(pollCtx)
	cancel()
	if err != nil {
		s.logger.Error("polling scan requests failed", "event", "poll.failed", "error", err.Error())
		return
	}
	if scanReq == nil {
		return
	}

	jobCtx, jobCancel := context.WithTimeout(ctx, timeoutCreateJob)
	// Cancellable for the same reason as handleCreateScan above.
	jobID, err := s.client.CreateScanJob(jobCtx, scanReq.TargetSpec, scanReq.PortSpec, true)
	jobCancel()
	if err != nil {
		s.logger.Error("creating scan job for scan request failed", "event", "poll.create_job_failed", "scan_request_id", scanReq.ID, "error", err.Error())
		return
	}

	s.logger.Info("scan request claimed", "event", "scan_request.claimed", "scan_request_id", scanReq.ID, "scan_job_id", jobID, "target", scanReq.TargetSpec, "ports", scanReq.PortSpec)

	state := newScanState(scanReq.TargetSpec, scanReq.PortSpec)
	s.mu.Lock()
	s.scans[jobID] = state
	s.mu.Unlock()

	s.runScan(jobID, scanReq.TargetSpec, scanReq.PortSpec, state)

	snapshot := state.snapshot()
	completeCtx, completeCancel := context.WithTimeout(context.Background(), timeoutCreateJob)
	defer completeCancel()
	if err := s.client.CompleteScanRequest(completeCtx, scanReq.ID, jobID, snapshot.Status); err != nil {
		s.logger.Error("reporting scan request completion failed", "event", "poll.complete_report_failed", "scan_request_id", scanReq.ID, "error", err.Error())
	}
}

// runScan runs a cancellable scan: scanCtx is registered in s.cancels
// under jobID for the duration of the pipeline stage, so
// StartCancelWatcher can cancel it from a separate goroutine while this
// function is blocked inside pipeline.RunScan (masscan/nmap etc. are all
// run via exec.CommandContext, so cancelling scanCtx kills whichever
// external process is currently running). Only ever reached with
// something to cancel when the caller created the job with
// cancellable=true (handleCreateScan, pollOnce) - callers that don't
// (main.go, tui/commands.go) never register anything here, but registering
// unconditionally is harmless and keeps this function the same for both.
func (s *Server) runScan(jobID, target, ports string, state *scanState) {
	start := time.Now()
	s.logger.Info("scan started", "event", "scan.started", "scan_job_id", jobID, "target", target, "ports", ports)

	// Fetched fresh for every scan rather than cached, so the webserver's
	// most current exclude list always takes effect; fetch failure aborts
	// the scan rather than proceeding unfiltered.
	excludes, err := s.client.GetExcludes(context.Background())
	if err != nil {
		state.setFailed(err)
		_ = s.client.CompleteScanJob(context.Background(), jobID, "failed")
		s.logger.Error("fetching excludes failed", "event", "scan.failed", "scan_job_id", jobID, "error", err.Error())
		return
	}
	// Same fetch-fresh, fail-closed treatment as excludes above.
	probeHostnames, err := s.client.GetProbeHostnames(context.Background())
	if err != nil {
		state.setFailed(err)
		_ = s.client.CompleteScanJob(context.Background(), jobID, "failed")
		s.logger.Error("fetching probe hostnames failed", "event", "scan.failed", "scan_job_id", jobID, "error", err.Error())
		return
	}

	scanCtx, cancelScan := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[jobID] = cancelScan
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.cancels, jobID)
		s.mu.Unlock()
		cancelScan()
	}()

	// Each host is submitted as soon as its own nmap+gowitness/RDP/TLS
	// work finishes, rather than batching the whole target range into one
	// submission after the entire scan completes - see pipeline.RunScan's
	// doc comment on why per-host, not per-port, is the achievable
	// granularity (masscan itself can't stream). A host whose submission
	// fails is logged and skipped, not treated as aborting the rest of
	// the scan - same tolerance as individual screenshot/RDP/TLS
	// submission failures always had.
	var tallyMu sync.Mutex
	var hostsSubmitted, openPorts, screenshots, rdpScreenshots, tlsCertificates int

	// Independent of state.appendLog above: that one backs this scanner's
	// own local /scans/:id (queried locally), this pushes to the webserver
	// instead - see internal/progress's doc comment.
	tracker := progress.NewTracker(s.client, jobID, progress.DefaultPushInterval)
	defer tracker.Close()

	result, err := pipeline.RunScan(scanCtx, s.pcfg, target, ports, excludes, probeHostnames,
		func(stage, message string) {
			state.appendLog("[" + stage + "] " + message)
			s.logger.Info(message, "event", "scan.progress", "scan_job_id", jobID, "stage", stage)
			tracker.Progress(stage, message)
		},
		func(host pipeline.HostResult) {
			defer pipeline.CleanupScreenshots([]pipeline.HostResult{host})

			submitCtx, cancel := context.WithTimeout(context.Background(), timeoutSubmit)
			defer cancel()
			err := s.client.SubmitHostResult(submitCtx, jobID, host, func(kind string, port int, err error) {
				state.appendLog(fmt.Sprintf("[%s] submission for %s failed", kind, host.IP))
				s.logger.Warn(kind+" submission failed", "event", "scan."+kind+"_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "port", port, "error", err.Error())
				tracker.Progress(kind, fmt.Sprintf("submission for %s failed: %v", host.IP, err))
			})
			if err != nil {
				state.appendLog("host submission for " + host.IP + " failed")
				s.logger.Warn("host submission failed, skipping", "event", "scan.host_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
				tracker.Progress("submit", fmt.Sprintf("host submission for %s failed: %v", host.IP, err))
				return
			}

			tallyMu.Lock()
			hostsSubmitted++
			openPorts += len(host.Ports)
			screenshots += len(host.Screenshots)
			rdpScreenshots += len(host.RDPScreenshots)
			tlsCertificates += len(host.TLSCertificates)
			tallyMu.Unlock()
			tracker.Progress("submit", fmt.Sprintf("submitted %s (%d open port(s))", host.IP, len(host.Ports)))

			s.logger.Info("host submitted", "event", "scan.host_submitted", "scan_job_id", jobID, "target_ip", host.IP, "open_ports", len(host.Ports))
		},
	)
	// Checked unconditionally, regardless of whether RunScan itself
	// returned an error: with streaming, a cancelled scan isn't
	// necessarily an all-or-nothing failure anymore - some hosts may
	// already have been reported (and submitted) before cancellation
	// took effect, in which case RunScan returns a nil error (it only
	// errors out if *every* host's nmap call failed). Checking only
	// inside "if err != nil" missed exactly that case: a scan cancelled
	// after partial success would otherwise be reported (and stored) as
	// "completed" instead of "cancelled". scanCtx.Err() is only ever
	// non-nil if we (StartCancelWatcher) called cancelScan, so this
	// reliably tells a deliberate stop apart from a genuine failure
	// regardless of how the underlying exec errors happened to surface.
	if scanCtx.Err() != nil {
		state.setCancelled()
		s.logger.Info("scan cancelled", "event", "scan.cancelled", "scan_job_id", jobID, "hosts_submitted", hostsSubmitted, "duration_ms", time.Since(start).Milliseconds())
		_ = s.client.CompleteScanJob(context.Background(), jobID, "cancelled")
		return
	}
	if err != nil {
		state.setFailed(err)
		s.logger.Error("scan failed", "event", "scan.failed", "scan_job_id", jobID, "error", err.Error(), "duration_ms", time.Since(start).Milliseconds())
		_ = s.client.CompleteScanJob(context.Background(), jobID, "failed")
		return
	}

	if err := s.client.CompleteScanJob(context.Background(), jobID, "completed"); err != nil {
		state.setFailed(err)
		s.logger.Error("reporting scan job completion failed", "event", "scan.complete_report_failed", "scan_job_id", jobID, "error", err.Error())
		return
	}
	state.setCompleted(result)

	s.logger.Info("scan completed",
		"event", "scan.completed",
		"scan_job_id", jobID,
		"target", target,
		"ports", ports,
		"hosts_found", len(result.Hosts),
		"hosts_submitted", hostsSubmitted,
		"open_ports_found", openPorts,
		"screenshots", screenshots,
		"rdp_screenshots", rdpScreenshots,
		"tls_certificates", tlsCertificates,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
