package updater

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"porttorch/scanner/internal/client"
)

// templateUpdateTimeout bounds the `nuclei -update-templates` run itself.
// Far more generous than httpTimeout: this clones/refreshes a template
// tree of several thousand files from GitHub, which on a slow link can
// legitimately take minutes. Bounded rather than unbounded so a hung
// download can't wedge the watcher goroutine for the process's lifetime.
const templateUpdateTimeout = 10 * time.Minute

// maxTemplateFailureReason caps how much of nuclei's own output is sent
// back as a failure reason - it's rendered directly on the Scanner Agents
// page, and nuclei can be verbose. The tail is kept rather than the head:
// the actual error is at the end, after whatever banner/progress output
// came first.
const maxTemplateFailureReason = 500

// templateUpdateClient is the subset of *client.Client this watcher
// needs, as an interface for the same testability reason as
// updateClient above.
type templateUpdateClient interface {
	CheckTemplateUpdateRequested(ctx context.Context) (bool, error)
	ReportTemplateUpdateOutcome(ctx context.Context, succeeded bool, failureReason string) error
	RefreshNucleiTemplatesUpdatedAt()
}

// StartTemplateUpdateWatcher blocks until ctx is done - the nuclei
// template counterpart to StartUpdateWatcher, started alongside it from
// "serve" mode only for the identical reason (scan/menu are one-shot
// processes with no background loop that could ever notice a request).
//
// Running the refresh from inside the scanner process is not incidental:
// nuclei's template tree lives under the *invoking user's* home directory
// (see pipeline.DefaultNucleiTemplatesDir), so a refresh triggered here
// necessarily writes the same tree this scanner's own scans read - which
// a manual `sudo nuclei -update-templates` on the host notably does not,
// since that writes root's home instead. Closing that footgun is a large
// part of why this button exists at all.
func StartTemplateUpdateWatcher(ctx context.Context, c *client.Client, busy BusyChecker, interval time.Duration, nucleiPath string, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndUpdateTemplates(ctx, c, busy, nucleiPath, log, defaultRunTemplateUpdate)
		}
	}
}

// runTemplateUpdate is injected so checkAndUpdateTemplates' control flow
// (busy-skip, success/failure reporting, the post-success re-stat) is
// unit-testable without a real nuclei binary or a real network fetch.
func checkAndUpdateTemplates(
	ctx context.Context,
	c templateUpdateClient,
	busy BusyChecker,
	nucleiPath string,
	log *slog.Logger,
	runTemplateUpdate func(ctx context.Context, nucleiPath string) (string, error),
) {
	checkCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	requested, err := c.CheckTemplateUpdateRequested(checkCtx)
	cancel()
	if err != nil {
		log.Error("checking nuclei template update request failed", "event", "template_update.check_failed", "error", err.Error())
		return
	}
	if !requested {
		return
	}

	// Same deferral as the binary self-update, for a different reason:
	// -update-templates rewrites the tree in place, and a scan already
	// running nuclei against it would be reading templates as they're
	// replaced. Waiting one tick for idle costs nothing.
	if busy.IsScanning() {
		log.Info("nuclei template update requested but a scan is in progress, deferring to next check", "event", "template_update.deferred")
		return
	}

	log.Info("refreshing nuclei templates", "event", "template_update.started")
	output, err := runTemplateUpdate(ctx, nucleiPath)
	if err != nil {
		reason := fmt.Sprintf("%v", err)
		if trimmed := tailOutput(output, maxTemplateFailureReason); trimmed != "" {
			reason = fmt.Sprintf("%v: %s", err, trimmed)
		}
		log.Error("nuclei template update failed", "event", "template_update.failed", "reason", reason)
		failCtx, failCancel := context.WithTimeout(ctx, httpTimeout)
		if reportErr := c.ReportTemplateUpdateOutcome(failCtx, false, reason); reportErr != nil {
			log.Error("reporting nuclei template update failure to webserver also failed", "event", "template_update.report_failed", "error", reportErr.Error())
		}
		failCancel()
		return
	}

	// Re-stat before reporting success, so the very next ingest request
	// already carries the new age - otherwise the dashboard would clear
	// the "update pending" badge while still showing the old, stale
	// template age until this process happened to refresh it for some
	// other reason, which reads exactly like the update did nothing.
	c.RefreshNucleiTemplatesUpdatedAt()

	succCtx, succCancel := context.WithTimeout(ctx, httpTimeout)
	if err := c.ReportTemplateUpdateOutcome(succCtx, true, ""); err != nil {
		log.Error("reporting nuclei template update success to webserver failed", "event", "template_update.report_failed", "error", err.Error())
	}
	succCancel()
	log.Info("nuclei templates refreshed", "event", "template_update.succeeded")
}

// defaultRunTemplateUpdate shells out to the same binary the nuclei scan
// stage itself uses (cfg.NucleiPath), so a deployment that pointed that
// at a non-default location gets the refresh applied to that install
// rather than whatever happens to be first on PATH. Returns nuclei's
// combined output either way - it's the only useful detail for a failure
// reason, and nuclei writes its errors to stderr.
func defaultRunTemplateUpdate(ctx context.Context, nucleiPath string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, templateUpdateTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, nucleiPath, "-update-templates")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// tailOutput returns the last max bytes of s, whitespace-trimmed, cut at
// a line boundary where possible so a truncated reason doesn't start
// mid-word.
func tailOutput(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	tail := s[len(s)-max:]
	if idx := strings.IndexByte(tail, '\n'); idx != -1 && idx+1 < len(tail) {
		tail = tail[idx+1:]
	}
	return strings.TrimSpace(tail)
}
