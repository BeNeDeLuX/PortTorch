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

	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/progress"
	"porttorch/scanner/internal/submitqueue"
)

// Server is the scanner's REST API, through which scans can be triggered
// remotely. Uses the same orchestrator as the TUI and the "scan" CLI
// subcommand.
type Server struct {
	echo   *echo.Echo
	client *client.Client
	pcfg   pipeline.Config
	// baseCfg is config.yaml exactly as loaded at startup. Dashboard
	// overrides are always applied on top of this rather than on top of
	// whatever pcfg currently holds, so clearing an override on the
	// dashboard genuinely restores the file's value instead of leaving
	// the last pushed one in place until a restart.
	baseCfg  pipeline.Config
	queueDir string
	// auditLog is shared across every scan this process ever runs (unlike
	// "scan"/"menu", which each open their own for a single scan) - see
	// internal/auditlog's doc comment. May be nil (open failed at
	// startup); Write/Close on a nil *AuditLog are safe no-ops.
	auditLog *auditlog.AuditLog
	token    string
	logger   *slog.Logger
	started  time.Time

	mu      sync.RWMutex
	scans   map[string]*scanState
	cancels map[string]context.CancelFunc
	// runningScans is the number of scans currently occupying a slot.
	// Deliberately its own counter rather than len(cancels): the queue
	// loop has to reserve a slot *before* it claims a request from the
	// webserver (claiming mutates scan_requests), so there is a window
	// where a slot is taken but no cancel func exists yet.
	runningScans int

	// pcfg and maxScans are read by every scan and written by the config
	// watcher (StartConfigWatcher), so they need their own lock.
	// Deliberately not s.mu: that one is held around scan bookkeeping,
	// and a scan starting shouldn't have to wait on, or block, a config
	// poll.
	cfgMu sync.RWMutex
	// maxScans is how many queued scan requests may run at once, and
	// baseMaxScans is config.yaml's own value - same base/override split
	// as pcfg/baseCfg, for the same reason (clearing a dashboard override
	// must restore the file's value, not the last pushed one).
	maxScans     int
	baseMaxScans int

	metricsMu    sync.Mutex
	scansTotal   map[string]int // keyed by terminal status: completed/failed/cancelled
	pollsFailed  int
	lastPollOK   time.Time
	lastPollFail time.Time
}

// NewServer builds the Echo app including routes. If token is non-empty,
// all requests must send an "Authorization: Bearer <token>" header. logger
// should be a JSON logger (see internal/logging) so that all stdout output
// of "serve" mode remains consistently machine-readable. queueDir is
// where a failed submission is durably queued for retry - see
// internal/submitqueue. auditLog may be nil (see the field's own doc
// comment). maxConcurrentScans caps how many queued scan requests run at
// once (see Config.MaxConcurrentScans); anything below 1 is treated as 1.
func NewServer(c *client.Client, pcfg pipeline.Config, maxConcurrentScans int, queueDir, token string, auditLog *auditlog.AuditLog, logger *slog.Logger) *Server {
	if maxConcurrentScans < 1 {
		maxConcurrentScans = 1
	}
	s := &Server{
		echo:         echo.New(),
		client:       c,
		pcfg:         pcfg,
		baseCfg:      pcfg,
		maxScans:     maxConcurrentScans,
		baseMaxScans: maxConcurrentScans,
		queueDir:     queueDir,
		auditLog:     auditLog,
		token:        token,
		logger:       logger,
		started:      time.Now(),
		scans:        make(map[string]*scanState),
		cancels:      make(map[string]context.CancelFunc),
		scansTotal:   make(map[string]int),
	}
	s.echo.HideBanner = true
	s.echo.HidePort = true
	s.echo.Use(middleware.Recover())
	s.echo.Use(s.accessLogMiddleware)
	if token != "" {
		s.echo.Use(s.authMiddleware)
	}

	s.echo.GET("/healthz", s.handleHealth)
	s.echo.GET("/metrics", s.handleMetrics)
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
	// nil nseScripts/nucleiProfile: this local REST endpoint (bypasses the
	// webserver's scan_requests queue entirely) has no scan-profile
	// concept - always runs DefaultNSEScripts and never runs nuclei, same
	// as before nuclei existed.
	// Occupies a slot like a queued scan does (see reserveScanSlot): this
	// one is never refused, but the queue loop must not pile more work on
	// top of a scan already running on this host.
	s.reserveScanSlot()
	go func() {
		defer s.releaseScanSlot()
		s.runScan(jobID, req.Target, req.Ports, nil, nil, nil, state)
	}()

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
			// Keeps claiming until the slots are full or the queue is
			// empty. pollOnce returns as soon as the scan is *started*
			// (it runs in its own goroutine), so this loop costs one HTTP
			// poll per claimed request and exactly one - as before - when
			// there is nothing queued.
			for s.pollOnce(ctx) {
			}
		}
	}
}

// StartCancelWatcher periodically checks whether an operator has
// requested that any currently-running, cancellable scan stop, and if so
// cancels its context. Its own goroutine/loop rather than a step inside
// StartPolling so that a cancellation is noticed on its own fixed
// interval, independently of how busy the queue loop happens to be.
// Blocks until ctx is done - typically started alongside s.Start() and
// StartPolling().
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

// pipelineConfig returns a snapshot of the current pipeline config.
// Config is a plain struct of value types, so the copy is complete and
// the caller can hold it for the whole scan without further locking.
func (s *Server) pipelineConfig() pipeline.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.pcfg
}

// StartConfigWatcher periodically fetches this agent's dashboard-managed
// config overrides and applies them in memory. Same shape and reasoning
// as StartCancelWatcher/StartUpdateWatcher: the webserver can never push
// anything to a scanner, so anything set on the dashboard has to be
// noticed by the scanner itself on its next poll.
//
// Its own loop rather than a step inside pollOnce, so that "lower the
// rate on this scanner, it's hammering a fragile segment" lands on a
// fixed interval during a long scan rather than whenever the queue loop
// next happens to have something to do.
//
// Overrides are applied to the in-memory config only; config.yaml on disk
// is never rewritten. A restart therefore falls back to the file, and the
// override is simply fetched again on the next tick - which also means a
// bad override can always be undone by clearing it on the dashboard, with
// no risk of having corrupted the file in the meantime.
func (s *Server) StartConfigWatcher(ctx context.Context, interval time.Duration) {
	s.refreshConfigOverrides(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshConfigOverrides(ctx)
		}
	}
}

func (s *Server) refreshConfigOverrides(ctx context.Context) {
	overrides, err := s.client.GetConfigOverrides(ctx)
	if err != nil {
		// Best-effort: a webserver that's briefly unreachable must not
		// change how this scanner is configured, so the previous values
		// simply stay in force.
		s.logger.Warn("fetching config overrides failed", "event", "scanner.config_fetch_failed", "err", err.Error())
		return
	}

	s.cfgMu.Lock()
	changed := applyConfigOverrides(&s.pcfg, s.baseCfg, overrides)
	if maxScans, ok := applyServeOverrides(&s.maxScans, s.baseMaxScans, overrides); ok {
		changed["maxConcurrentScans"] = maxScans
	}
	s.cfgMu.Unlock()

	if len(changed) > 0 {
		s.logger.Info("applied dashboard config overrides", "event", "scanner.config_applied", "settings", changed)
	}
	// The reported limit has to follow a changed maxConcurrentScans, or
	// the dashboard would keep showing the old capacity until the next
	// scan started or finished.
	s.PublishScanSlots()
}

// applyServeOverrides is applyConfigOverrides' counterpart for the
// serve-mode tunables that aren't pipeline settings. Kept separate rather
// than folded into pipeline.Config: maxConcurrentScans governs how many
// scans this process runs at once, and putting it on the struct that gets
// handed to RunScan would give every scan a field about the queue it
// knows nothing about.
//
// Same base-first semantics: clearing the override on the dashboard
// restores config.yaml's own value. Reports the new value and whether it
// actually changed.
func applyServeOverrides(maxScans *int, base int, overrides map[string]int) (int, bool) {
	before := *maxScans
	*maxScans = base
	if value, ok := overrides["maxConcurrentScans"]; ok && value >= 1 {
		*maxScans = value
	}
	return *maxScans, *maxScans != before
}

// applyConfigOverrides overlays overrides onto cfg, starting from base -
// the config as loaded from config.yaml at startup.
//
// Resetting to base first is what makes *removing* an override on the
// dashboard actually take effect: without it, clearing a setting would
// leave the last pushed value in memory until the process restarted,
// which is the opposite of what clearing it means. Returns the settings
// whose value actually changed, so the log line only appears when
// something really did.
//
// An unknown key is ignored rather than rejected: the dashboard validates
// against its own allowlist, and a scanner older than a newly added
// tunable should keep working, not fail.
func applyConfigOverrides(cfg *pipeline.Config, base pipeline.Config, overrides map[string]int) map[string]int {
	before := *cfg
	*cfg = base

	targets := map[string]*int{
		"masscanRate":              &cfg.MasscanRate,
		"masscanRetries":           &cfg.MasscanRetries,
		"concurrency":              &cfg.Concurrency,
		"gowitnessConcurrency":     &cfg.GowitnessConcurrency,
		"screenshotTimeoutSeconds": &cfg.ScreenshotTimeoutSeconds,
		"rdpConcurrency":           &cfg.RDPConcurrency,
		"nucleiConcurrency":        &cfg.NucleiConcurrency,
		"nucleiTimeoutSeconds":     &cfg.NucleiTimeoutSeconds,
		"tlsCertTimeoutSeconds":    &cfg.TLSCertTimeoutSeconds,
	}
	for key, value := range overrides {
		if target, ok := targets[key]; ok {
			*target = value
		}
	}

	changed := map[string]int{}
	for key, target := range targets {
		if wasDifferent(before, *cfg, key) {
			changed[key] = *target
		}
	}
	return changed
}

// wasDifferent compares one named field across two configs. Written out
// rather than done with reflection: nine fields, and an explicit list
// can't silently start reporting on a field nobody meant to expose.
func wasDifferent(a, b pipeline.Config, key string) bool {
	switch key {
	case "masscanRate":
		return a.MasscanRate != b.MasscanRate
	case "masscanRetries":
		return a.MasscanRetries != b.MasscanRetries
	case "concurrency":
		return a.Concurrency != b.Concurrency
	case "gowitnessConcurrency":
		return a.GowitnessConcurrency != b.GowitnessConcurrency
	case "screenshotTimeoutSeconds":
		return a.ScreenshotTimeoutSeconds != b.ScreenshotTimeoutSeconds
	case "rdpConcurrency":
		return a.RDPConcurrency != b.RDPConcurrency
	case "nucleiConcurrency":
		return a.NucleiConcurrency != b.NucleiConcurrency
	case "nucleiTimeoutSeconds":
		return a.NucleiTimeoutSeconds != b.NucleiTimeoutSeconds
	case "tlsCertTimeoutSeconds":
		return a.TLSCertTimeoutSeconds != b.TLSCertTimeoutSeconds
	}
	return false
}

// IsScanning reports whether this process currently has a scan in
// progress - satisfies internal/updater's BusyChecker interface. s.cancels
// only ever holds an entry for the duration of runScan's pipeline.RunScan
// call (registered and deleted around it, see runScan below), so a
// non-empty map is a reliable proxy for "a scan is actively running right
// now", not just queued/completed.
func (s *Server) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cancels) > 0
}

// tryAcquireScanSlot reserves one of the maxScans slots for a scan the
// queue loop is about to claim, or reports false if they are all busy.
//
// Reserved before the claim rather than after, because claiming mutates
// scan_requests on the webserver: a request claimed and then not run
// would sit there looking like this scanner was working on it.
func (s *Server) tryAcquireScanSlot() bool {
	limit := s.maxConcurrentScans()
	s.mu.Lock()
	if s.runningScans >= limit {
		s.mu.Unlock()
		return false
	}
	s.runningScans++
	running := s.runningScans
	s.mu.Unlock()
	s.client.SetScanSlots(running, limit)
	return true
}

// reserveScanSlot takes a slot without checking the limit. Used by the
// local REST endpoint, which is an explicit action taken by someone on
// this host and so is never refused - but it still occupies a slot, so
// the queue loop backs off while it runs rather than piling more work on
// top of it.
func (s *Server) reserveScanSlot() {
	s.mu.Lock()
	s.runningScans++
	running := s.runningScans
	s.mu.Unlock()
	s.client.SetScanSlots(running, s.maxConcurrentScans())
}

func (s *Server) releaseScanSlot() {
	s.mu.Lock()
	if s.runningScans > 0 {
		s.runningScans--
	}
	running := s.runningScans
	s.mu.Unlock()
	s.client.SetScanSlots(running, s.maxConcurrentScans())
}

// PublishScanSlots pushes the current slot usage to the client so it rides
// along on the next request's X-Scanner-Scan-Slots header. Called once at
// startup (so an idle scanner reports "0/N" rather than nothing until its
// first scan) and again whenever the dashboard changes the limit.
func (s *Server) PublishScanSlots() {
	s.mu.RLock()
	running := s.runningScans
	s.mu.RUnlock()
	s.client.SetScanSlots(running, s.maxConcurrentScans())
}

func (s *Server) maxConcurrentScans() int {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.maxScans
}

// StartRetryWatcher periodically drains the submit queue (see
// internal/submitqueue) in the background - the "serve" process is the
// only entry point long-running enough for this to matter; "scan"/"menu"
// only ever drain once, at the very start of their single run. Blocks
// until ctx is done - typically started alongside s.Start()/StartPolling()/
// StartCancelWatcher().
func (s *Server) StartRetryWatcher(ctx context.Context, interval time.Duration) {
	submitqueue.StartRetryWatcher(ctx, s.queueDir, s.client, interval, func(result submitqueue.DrainResult) {
		s.client.SetSubmitQueuePending(result.Pending)
		if result.Empty() {
			return
		}
		s.logger.Info("submit queue drained", "event", "submitqueue.drained", "succeeded", result.Succeeded, "gave_up", result.GaveUp, "pending", result.Pending, "dropped", result.Dropped, "rejected", result.Rejected)
	})
}

func (s *Server) recordPollResult(ok bool) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	if ok {
		s.lastPollOK = time.Now()
	} else {
		s.pollsFailed++
		s.lastPollFail = time.Now()
	}
}

func (s *Server) recordScanResult(status string) {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	s.scansTotal[status]++
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

// pollOnce claims at most one queued scan request and starts it in the
// background, reporting whether it actually claimed one.
//
// Slot ownership: the slot is taken here and, once a scan has been
// started, handed to that scan's own goroutine, which releases it when
// the scan finishes. Every path that returns without starting a scan
// releases it itself.
func (s *Server) pollOnce(ctx context.Context) bool {
	if !s.tryAcquireScanSlot() {
		return false
	}
	slotHandedOver := false
	defer func() {
		if !slotHandedOver {
			s.releaseScanSlot()
		}
	}()

	pollCtx, cancel := context.WithTimeout(ctx, timeoutCreateJob)
	scanReq, err := s.client.PollNextScanRequest(pollCtx)
	cancel()
	if err != nil {
		s.recordPollResult(false)
		s.logger.Error("polling scan requests failed", "event", "poll.failed", "error", err.Error())
		return false
	}
	s.recordPollResult(true)
	if scanReq == nil {
		return false
	}

	jobCtx, jobCancel := context.WithTimeout(ctx, timeoutCreateJob)
	// Cancellable for the same reason as handleCreateScan above.
	jobID, err := s.client.CreateScanJob(jobCtx, scanReq.TargetSpec, scanReq.PortSpec, true)
	jobCancel()
	if err != nil {
		s.logger.Error("creating scan job for scan request failed", "event", "poll.create_job_failed", "scan_request_id", scanReq.ID, "error", err.Error())
		return false
	}

	s.logger.Info("scan request claimed", "event", "scan_request.claimed", "scan_request_id", scanReq.ID, "scan_job_id", jobID, "target", scanReq.TargetSpec, "ports", scanReq.PortSpec)

	state := newScanState(scanReq.TargetSpec, scanReq.PortSpec)
	s.mu.Lock()
	s.scans[jobID] = state
	s.mu.Unlock()

	slotHandedOver = true
	go func() {
		defer s.releaseScanSlot()

		s.runScan(jobID, scanReq.TargetSpec, scanReq.PortSpec, resolveNSEScripts(scanReq.NSEProfile, scanReq.NSEScripts), resolveNucleiProfile(scanReq.NucleiProfile, scanReq.NucleiTags), scanReq.MasscanRate, state)

		snapshot := state.snapshot()
		// context.Background(), not ctx: the scan is over either way and
		// the webserver still needs to be told, even if the process is
		// shutting down and ctx has already been cancelled.
		completeCtx, completeCancel := context.WithTimeout(context.Background(), timeoutCreateJob)
		defer completeCancel()
		if err := s.client.CompleteScanRequest(completeCtx, scanReq.ID, jobID, snapshot.Status); err != nil {
			s.logger.Error("reporting scan request completion failed", "event", "poll.complete_report_failed", "scan_request_id", scanReq.ID, "error", err.Error())
		}
	}()

	return true
}

// resolveNSEScripts turns a webserver-provided scan-profile kind + optional
// custom list into the concrete []string RunNmap needs. "default" (or any
// unrecognized/empty value - e.g. a pre-migration scan_requests row, or an
// older webserver that doesn't send a profile at all) maps to nil, which
// RunNmap's own fallback already treats as "use DefaultNSEScripts" - so
// this never needs its own copy of that list.
func resolveNSEScripts(profile string, custom []string) []string {
	switch profile {
	case "all_safe":
		return pipeline.AllSafeNSEScripts
	case "custom":
		return custom
	default:
		return nil
	}
}

// resolveNucleiProfile is resolveNSEScripts' nuclei equivalent: turns a
// webserver-provided profile kind + optional custom tag list into the
// *pipeline.NucleiProfile RunScan needs. "off" (or any unrecognized/empty
// value - a pre-nuclei scan_requests row, or an older webserver that
// doesn't send this at all) resolves to nil, which RunScan's own doc
// comment already documents as "nuclei doesn't run at all" - so an
// un-upgraded caller reproduces exactly today's (pre-nuclei) behavior.
// "safe" excludes nuclei's own dos/fuzz/intrusive tag conventions rather
// than naming an allowlist - unlike NSE's "All Safe Modules", nuclei has
// no single stable "safe" category to point at (its tag taxonomy has
// thousands of entries and grows with every template release), so this is
// the same "safe means excluding the risky, not enumerating everything
// else" approach the frontend's Scan Profiles warning already applies to
// custom NSE profiles containing Active Modules scripts.
func resolveNucleiProfile(profile string, tags []string) *pipeline.NucleiProfile {
	switch profile {
	case "safe":
		return &pipeline.NucleiProfile{ExcludeTags: []string{"dos", "fuzz", "intrusive"}}
	case "custom":
		return &pipeline.NucleiProfile{Tags: tags}
	default:
		return nil
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
func (s *Server) runScan(jobID, target, ports string, nseScripts []string, nucleiProfile *pipeline.NucleiProfile, masscanRate *int, state *scanState) {
	start := time.Now()
	s.logger.Info("scan started", "event", "scan.started", "scan_job_id", jobID, "target", target, "ports", ports)

	// Cheap re-stat so a serve process that has been up for weeks reports
	// the templates it will actually use for this scan, not the ones it
	// found at startup - someone may have run `nuclei -update-templates`
	// on the host since.
	s.client.RefreshNucleiTemplatesUpdatedAt()

	// Fetched fresh for every scan rather than cached, so the webserver's
	// most current exclude list always takes effect; fetch failure aborts
	// the scan rather than proceeding unfiltered.
	excludes, err := s.client.GetExcludes(context.Background())
	if err != nil {
		state.setFailed(err)
		s.recordScanResult("failed")
		_ = s.client.CompleteScanJob(context.Background(), jobID, "failed")
		s.logger.Error("fetching excludes failed", "event", "scan.failed", "scan_job_id", jobID, "error", err.Error())
		return
	}
	// Same fetch-fresh, fail-closed treatment as excludes above.
	probeHostnames, err := s.client.GetProbeHostnames(context.Background())
	if err != nil {
		state.setFailed(err)
		s.recordScanResult("failed")
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

	// A per-scan rate override applies to this scan only - s.pcfg is
	// copied (Config is a plain struct passed by value), never mutated, so
	// a slow one-off scan can't quietly re-rate every later scan this
	// long-running serve process handles. Taking the copy under the lock
	// also means a scan runs against one coherent config even if the
	// config watcher updates it mid-scan.
	scanCfg := s.pipelineConfig()
	if masscanRate != nil && *masscanRate > 0 {
		scanCfg.MasscanRate = *masscanRate
	}

	result, err := pipeline.RunScan(scanCtx, scanCfg, target, ports, excludes, probeHostnames, nseScripts, nucleiProfile,
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
				if submitqueue.IsPermanentFailure(err) {
					// The webserver definitively rejected this exact
					// payload (a 4xx) - retrying it unchanged would never
					// succeed, so it's not worth queuing at all.
					state.appendLog("host submission for " + host.IP + " was rejected (not retried)")
					s.logger.Error("host submission rejected by webserver, not queuing for retry", "event", "scan.host_submit_rejected", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
					tracker.Progress("submit", fmt.Sprintf("host submission for %s was rejected (not retried): %v", host.IP, err))
				} else {
					state.appendLog("host submission for " + host.IP + " failed, queued for retry")
					s.logger.Warn("host submission failed, queuing for retry", "event", "scan.host_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
					tracker.Progress("submit", fmt.Sprintf("host submission for %s failed, queued for retry: %v", host.IP, err))
					if queueErr := submitqueue.Enqueue(s.queueDir, jobID, host); queueErr != nil {
						s.logger.Error("queuing failed host submission for retry also failed, result lost", "event", "submitqueue.enqueue_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", queueErr.Error())
					} else {
						s.client.SetSubmitQueuePending(submitqueue.CountPending(s.queueDir))
					}
				}
				if writeErr := s.auditLog.Write(auditlog.EntryFromHost(jobID, host, false)); writeErr != nil {
					s.logger.Warn("writing scan audit log entry failed", "event", "auditlog.write_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", writeErr.Error())
				}
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
			if writeErr := s.auditLog.Write(auditlog.EntryFromHost(jobID, host, true)); writeErr != nil {
				s.logger.Warn("writing scan audit log entry failed", "event", "auditlog.write_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", writeErr.Error())
			}
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
		s.recordScanResult("cancelled")
		s.logger.Info("scan cancelled", "event", "scan.cancelled", "scan_job_id", jobID, "hosts_submitted", hostsSubmitted, "duration_ms", time.Since(start).Milliseconds())
		_ = s.client.CompleteScanJob(context.Background(), jobID, "cancelled")
		return
	}
	if err != nil {
		state.setFailed(err)
		s.recordScanResult("failed")
		s.logger.Error("scan failed", "event", "scan.failed", "scan_job_id", jobID, "error", err.Error(), "duration_ms", time.Since(start).Milliseconds())
		_ = s.client.CompleteScanJob(context.Background(), jobID, "failed")
		return
	}

	if err := s.client.CompleteScanJob(context.Background(), jobID, "completed"); err != nil {
		state.setFailed(err)
		s.recordScanResult("failed")
		s.logger.Error("reporting scan job completion failed", "event", "scan.complete_report_failed", "scan_job_id", jobID, "error", err.Error())
		return
	}
	state.setCompleted(result)
	s.recordScanResult("completed")

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
