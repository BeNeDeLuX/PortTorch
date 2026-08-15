package tui

import (
	"context"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
	// Aliased - this file already uses "progress" as the naming prefix for
	// its own bubbletea message type (progressMsg/progressCh/waitForProgress),
	// unrelated to this package.
	scanprogress "porttorch/scanner/internal/progress"
	"porttorch/scanner/internal/submitqueue"
)

func createScanJobCmd(c *client.Client, target, ports string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Not cancellable: the menu TUI has nothing polling during the
		// blocking scan below (see CreateScanJob's doc comment).
		jobID, err := c.CreateScanJob(ctx, target, ports, false)
		return jobCreatedMsg{jobID: jobID, err: err}
	}
}

// waitForProgress reads exactly one progress message from the channel.
// After processing it in Update(), the caller must return this command
// again to keep listening.
func waitForProgress(ch <-chan progressMsg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

// runScanCmd runs the scan and submits each host as soon as its own
// nmap+gowitness/RDP/TLS work finishes, rather than waiting for the whole
// scan to complete first - see pipeline.RunScan's HostCompleteFunc. Also
// reports the final scan_job status itself (completed/failed) before
// returning, since there's no separate "finalize" step anymore once
// submission is interleaved with scanning.
func runScanCmd(c *client.Client, pcfg pipeline.Config, queueDir string, auditLog *auditlog.AuditLog, jobID, target, ports string, progressCh chan<- progressMsg) tea.Cmd {
	return func() tea.Msg {
		// Opportunistically flushes any backlog left behind by a prior
		// run's submission failures before this run's own scan starts -
		// see internal/submitqueue's doc comment. The menu TUI has no
		// ongoing background loop to retry from later (unlike "serve"),
		// so "once, at the start of each scan" is its only chance.
		drained := submitqueue.Drain(context.Background(), queueDir, c)
		c.SetSubmitQueuePending(drained.Pending)
		if !drained.Empty() {
			progressCh <- progressMsg{stage: "submitqueue", message: fmt.Sprintf("retry queue: %d succeeded, %d gave up, %d rejected, %d dropped (corrupt), %d still pending", drained.Succeeded, drained.GaveUp, drained.Rejected, drained.Dropped, drained.Pending)}
		}

		// Fetched fresh rather than cached, so the webserver's most
		// current exclude list always takes effect; fetch failure aborts
		// the scan rather than proceeding unfiltered.
		excludes, err := c.GetExcludes(context.Background())
		if err != nil {
			_ = c.CompleteScanJob(context.Background(), jobID, "failed")
			return scanDoneMsg{err: fmt.Errorf("fetching excludes: %w", err)}
		}
		// Same fetch-fresh, fail-closed treatment as excludes above.
		probeHostnames, err := c.GetProbeHostnames(context.Background())
		if err != nil {
			_ = c.CompleteScanJob(context.Background(), jobID, "failed")
			return scanDoneMsg{err: fmt.Errorf("fetching probe hostnames: %w", err)}
		}

		var tallyMu sync.Mutex
		var screenshotErrors int

		tracker := scanprogress.NewTracker(c, jobID, scanprogress.DefaultPushInterval)
		defer tracker.Close()

		// nil nseScripts: the menu TUI has no scan-profile concept - always
		// runs DefaultNSEScripts, same as before this feature existed.
		result, scanErr := pipeline.RunScan(context.Background(), pcfg, target, ports, excludes, probeHostnames, nil,
			func(stage, message string) {
				progressCh <- progressMsg{stage: stage, message: message}
				tracker.Progress(stage, message)
			},
			func(host pipeline.HostResult) {
				defer pipeline.CleanupScreenshots([]pipeline.HostResult{host})

				submitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				err := c.SubmitHostResult(submitCtx, jobID, host, func(kind string, port int, err error) {
					tallyMu.Lock()
					screenshotErrors++
					tallyMu.Unlock()
					msg := fmt.Sprintf("submission for %s failed: %v", host.IP, err)
					progressCh <- progressMsg{stage: kind, message: msg}
					tracker.Progress(kind, msg)
				})
				if err != nil {
					_ = auditLog.Write(auditlog.EntryFromHost(jobID, host, false))
					if submitqueue.IsPermanentFailure(err) {
						// The webserver definitively rejected this exact
						// payload (a 4xx) - retrying it unchanged would
						// never succeed, so it's not worth queuing at all.
						msg := fmt.Sprintf("host submission for %s was rejected (not retried): %v", host.IP, err)
						progressCh <- progressMsg{stage: "submit", message: msg}
						tracker.Progress("submit", msg)
						return
					}
					if queueErr := submitqueue.Enqueue(queueDir, jobID, host); queueErr != nil {
						msg := fmt.Sprintf("host submission for %s failed and could not be queued for retry, result lost: %v", host.IP, queueErr)
						progressCh <- progressMsg{stage: "submit", message: msg}
						tracker.Progress("submit", msg)
						return
					}
					c.SetSubmitQueuePending(submitqueue.CountPending(queueDir))
					msg := fmt.Sprintf("host submission for %s failed, queued for retry: %v", host.IP, err)
					progressCh <- progressMsg{stage: "submit", message: msg}
					tracker.Progress("submit", msg)
					return
				}
				_ = auditLog.Write(auditlog.EntryFromHost(jobID, host, true))
				submittedMsg := fmt.Sprintf("submitted %s (%d open port(s))", host.IP, len(host.Ports))
				progressCh <- progressMsg{stage: "submit", message: submittedMsg}
				tracker.Progress("submit", submittedMsg)
			},
		)

		status := "completed"
		if scanErr != nil {
			status = "failed"
		}
		_ = c.CompleteScanJob(context.Background(), jobID, status)

		return scanDoneMsg{result: result, err: scanErr, screenshotErrors: screenshotErrors}
	}
}
