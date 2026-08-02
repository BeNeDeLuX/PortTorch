package tui

import (
	"context"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
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
func runScanCmd(c *client.Client, pcfg pipeline.Config, jobID, target, ports string, progressCh chan<- progressMsg) tea.Cmd {
	return func() tea.Msg {
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

		result, scanErr := pipeline.RunScan(context.Background(), pcfg, target, ports, excludes, probeHostnames,
			func(stage, message string) {
				progressCh <- progressMsg{stage: stage, message: message}
			},
			func(host pipeline.HostResult) {
				defer pipeline.CleanupScreenshots([]pipeline.HostResult{host})

				submitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				err := c.SubmitHostResult(submitCtx, jobID, host, func(kind string, port int, err error) {
					tallyMu.Lock()
					screenshotErrors++
					tallyMu.Unlock()
					progressCh <- progressMsg{stage: kind, message: fmt.Sprintf("submission for %s failed: %v", host.IP, err)}
				})
				if err != nil {
					progressCh <- progressMsg{stage: "submit", message: fmt.Sprintf("host submission for %s failed: %v", host.IP, err)}
					return
				}
				progressCh <- progressMsg{stage: "submit", message: fmt.Sprintf("submitted %s (%d open port(s))", host.IP, len(host.Ports))}
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
