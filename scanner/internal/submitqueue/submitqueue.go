// Package submitqueue durably persists a host's scan result to disk when
// submitting it to the webserver fails, so it can be retried later
// instead of being lost outright.
//
// Without this, a submission failure (e.g. the webserver is briefly
// unreachable mid-scan) is genuinely unrecoverable: every one of the
// three entry points (scan/menu/serve) calls pipeline.CleanupScreenshots
// right after the submission attempt regardless of outcome, deleting the
// only copy of that host's screenshot files - the host/port data itself
// has nowhere else to go either, since streaming submission means there's
// no final "resubmit everything" step at the end of a scan. A brief
// webserver outage during a long scan therefore used to mean silently and
// permanently losing every host result submitted during that window.
//
// Deliberately file-based rather than in-memory: a queued entry has to
// survive the current process exiting (a one-shot "scan"/"menu" run
// finishing, or "serve" itself restarting) and still be retried by
// whichever invocation runs next.
package submitqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
)

// maxAttempts bounds how many times Drain retries one queued entry before
// giving up on it for good - mirrors the webserver's own scanner
// self-update MAX_UPDATE_ATTEMPTS. A submission that's failed this many
// times is far more likely permanently invalid (e.g. rejected by the
// webserver's own validation) than transiently unreachable, and retrying
// it forever would just accumulate garbage on disk indefinitely.
const maxAttempts = 10

// maxAge bounds how long a queued entry is kept regardless of attempt
// count - a host result this stale has limited value even if eventually
// resubmitted successfully.
const maxAge = 7 * 24 * time.Hour

// IsPermanentFailure reports whether err indicates the webserver
// definitively rejected the submission (a 4xx status - the payload
// itself is invalid or disallowed) rather than being transiently
// unreachable (a network error, timeout, or 5xx - worth retrying). A 4xx
// will fail identically no matter how many times the exact same payload
// is resubmitted, so Enqueue/Drain both use this to avoid wasting a
// retry attempt (or a disk write in Enqueue's case) on something that
// can never succeed.
func IsPermanentFailure(err error) bool {
	var httpErr *client.HTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
	}
	return false
}

type queuedItem struct {
	JobID    string              `json:"jobId"`
	Host     pipeline.HostResult `json:"host"`
	QueuedAt time.Time           `json:"queuedAt"`
	Attempts int                 `json:"attempts"`
}

// Enqueue durably persists host (which failed to submit under jobID) into
// queueDir, for a later Drain call to retry. Returns an error only when
// persisting itself failed (e.g. queueDir isn't writable) - in that case
// the host result is lost entirely, both the live submission and the
// durable copy having failed, which the caller should log clearly rather
// than treating as an ordinary "will retry" outcome.
func Enqueue(queueDir, jobID string, host pipeline.HostResult) error {
	if err := os.MkdirAll(queueDir, 0o755); err != nil {
		return fmt.Errorf("creating submit queue directory: %w", err)
	}
	entryDir, err := os.MkdirTemp(queueDir, "entry-*")
	if err != nil {
		return fmt.Errorf("creating submit queue entry: %w", err)
	}

	// A fresh copy of the image-bearing slices, not a mutation of the
	// caller's own host - every call site still needs the *original*
	// ImagePath values immediately after this call, to pass to
	// pipeline.CleanupScreenshots. If this function rewrote them in
	// place, that cleanup would target this new queue directory instead
	// of the actual temp directory it's meant to remove.
	queued := host
	queued.Screenshots = make([]pipeline.Screenshot, len(host.Screenshots))
	copy(queued.Screenshots, host.Screenshots)
	for i := range queued.Screenshots {
		if newPath, copyErr := copyImage(entryDir, fmt.Sprintf("screenshot-%d.png", i), queued.Screenshots[i].ImagePath); copyErr == nil {
			queued.Screenshots[i].ImagePath = newPath
		} else {
			// Best-effort: the host/port data and every other
			// screenshot/certificate are still worth queuing even if one
			// particular image failed to copy.
			queued.Screenshots[i].ImagePath = ""
		}
	}
	queued.RDPScreenshots = make([]pipeline.RDPScreenshot, len(host.RDPScreenshots))
	copy(queued.RDPScreenshots, host.RDPScreenshots)
	for i := range queued.RDPScreenshots {
		if newPath, copyErr := copyImage(entryDir, fmt.Sprintf("rdp-%d.png", i), queued.RDPScreenshots[i].ImagePath); copyErr == nil {
			queued.RDPScreenshots[i].ImagePath = newPath
		} else {
			queued.RDPScreenshots[i].ImagePath = ""
		}
	}

	data, err := json.Marshal(queuedItem{JobID: jobID, Host: queued, QueuedAt: time.Now()})
	if err != nil {
		os.RemoveAll(entryDir)
		return fmt.Errorf("encoding queued item: %w", err)
	}
	if err := os.WriteFile(filepath.Join(entryDir, "item.json"), data, 0o644); err != nil {
		os.RemoveAll(entryDir)
		return fmt.Errorf("writing queued item: %w", err)
	}
	return nil
}

func copyImage(entryDir, filename, srcPath string) (string, error) {
	if srcPath == "" {
		return "", fmt.Errorf("empty source path")
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", err
	}
	dstPath := filepath.Join(entryDir, filename)
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		return "", err
	}
	return dstPath, nil
}

// DrainResult summarizes what happened during one Drain call, for the
// caller to log however fits its own reporting mechanism (a *slog.Logger
// for scan/serve, the progress channel + tracker for the menu TUI, which
// has no stdout logging of its own at all - see internal/logging's doc
// comment on why).
type DrainResult struct {
	Succeeded int
	GaveUp    int
	Pending   int
	// Dropped counts entries removed because they were corrupt (an
	// unreadable or unparseable item.json) - distinct from GaveUp, which
	// is a well-formed entry that kept failing to submit. Both are
	// "gone, unrecoverable" outcomes, but corruption is worth surfacing
	// differently: it points at a bug in Enqueue or the filesystem
	// itself, not an unreachable/rejecting webserver.
	Dropped int
	// Rejected counts entries removed after a single attempt because the
	// webserver responded with a 4xx (see IsPermanentFailure) - distinct
	// from GaveUp (which exhausted maxAttempts/maxAge retrying a
	// transient-looking failure), since a 4xx means the exact same
	// payload will never succeed no matter how many more times it's
	// retried, worth telling apart from "we tried and it kept timing out".
	Rejected int
}

func (r DrainResult) Empty() bool {
	return r.Succeeded == 0 && r.GaveUp == 0 && r.Pending == 0 && r.Dropped == 0 && r.Rejected == 0
}

// PendingEntry is one queued host result, for showing an operator what
// is stuck rather than only how many things are. CountPending answers
// "how many" for the header the scanner reports to the dashboard; this
// answers "which ones, since when, and how often has it been tried" -
// the questions you actually have while sitting on the scanner host with
// the webserver unreachable.
type PendingEntry struct {
	ID       string
	JobID    string
	IP       string
	Ports    int
	QueuedAt time.Time
	Attempts int
}

// ListPending reads the queue without touching it. Same "a missing or
// unreadable directory is an empty queue, not a failure" treatment as
// Drain and CountPending, since most scanners never queue anything at
// all; an entry that fails to parse is skipped rather than aborting the
// listing, so one corrupt file cannot hide the rest.
func ListPending(queueDir string) []PendingEntry {
	dirEntries, err := os.ReadDir(queueDir)
	if err != nil {
		return nil
	}
	var out []PendingEntry
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(queueDir, dirEntry.Name(), "item.json"))
		if err != nil {
			continue
		}
		var item queuedItem
		if err := json.Unmarshal(data, &item); err != nil {
			continue
		}
		open := 0
		for _, port := range item.Host.Ports {
			if port.State == "open" {
				open++
			}
		}
		out = append(out, PendingEntry{
			ID:       dirEntry.Name(),
			JobID:    item.JobID,
			IP:       item.Host.IP,
			Ports:    open,
			QueuedAt: item.QueuedAt,
			Attempts: item.Attempts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.Before(out[j].QueuedAt) })
	return out
}

// DiscardPending deletes every queued entry without attempting to submit
// it. The escape hatch for a queue that can never drain - results for a
// scan job the webserver no longer has, or a backlog an operator has
// decided to abandon - which is otherwise only reachable by deleting the
// directory by hand. Returns how many entries were removed.
func DiscardPending(queueDir string) (int, error) {
	dirEntries, err := os.ReadDir(queueDir)
	if err != nil {
		return 0, nil
	}
	removed := 0
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(queueDir, dirEntry.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// Drain attempts to resubmit every currently-queued host result via c,
// deleting each entry that either succeeds, has exceeded maxAttempts/
// maxAge (see the "gave up" case), or gets a definitive 4xx rejection
// (see IsPermanentFailure - retrying that unchanged would never succeed,
// so it's removed on the very first attempt rather than consuming
// maxAttempts worth of pointless retries). An entry that's still failing
// transiently but hasn't hit either limit yet has its attempt count
// incremented and is left in place for a future Drain call.
//
// Safe to call against an empty or nonexistent queueDir (the common case
// - most scans never fail a submission at all): ReadDir's error is
// treated as "nothing to drain", not a failure. Called opportunistically
// at the start of every scanner invocation (scan/menu/serve), so a
// backlog from a prior run's outage doesn't wait indefinitely for a lucky
// retry window, and periodically during "serve" mode's own long-running
// operation (see StartRetryWatcher) so a backlog accumulated mid-scan
// doesn't have to wait for the process to restart either.
func Drain(ctx context.Context, queueDir string, c *client.Client) DrainResult {
	var result DrainResult

	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		drainEntry(ctx, filepath.Join(queueDir, entry.Name()), c, &result)
	}
	return result
}

// CountPending returns how many entries currently sit in queueDir waiting
// for a future Drain call - a lightweight directory listing, not a Drain
// itself. Used to keep client.Client's reported backlog size (see
// SetSubmitQueuePending) accurate immediately after an Enqueue, rather
// than only after the next periodic Drain runs. Safe against a missing/
// empty queueDir, same "nothing to report" treatment as Drain itself.
func CountPending(queueDir string) int {
	entries, err := os.ReadDir(queueDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	return count
}

func drainEntry(ctx context.Context, entryDir string, c *client.Client, result *DrainResult) {
	itemPath := filepath.Join(entryDir, "item.json")
	data, err := os.ReadFile(itemPath)
	if err != nil {
		// An entry directory without a readable item.json can never
		// succeed - remove it so it doesn't sit there forever confusing
		// future Drain calls, same as CleanupScreenshots' own silent
		// best-effort os.RemoveAll.
		os.RemoveAll(entryDir)
		result.Dropped++
		return
	}

	var item queuedItem
	if err := json.Unmarshal(data, &item); err != nil {
		os.RemoveAll(entryDir)
		result.Dropped++
		return
	}

	submitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	submitErr := c.SubmitHostResult(submitCtx, item.JobID, item.Host, func(kind string, port int, err error) {
		// Individual screenshot/RDP/TLS-certificate sub-item failures
		// during a retry are the same "supplement, not primary data"
		// case SubmitHostResult already documents - not a reason to
		// treat the whole retry as failed.
	})
	if submitErr == nil {
		os.RemoveAll(entryDir)
		result.Succeeded++
		return
	}
	if IsPermanentFailure(submitErr) {
		os.RemoveAll(entryDir)
		result.Rejected++
		return
	}

	item.Attempts++
	if item.Attempts >= maxAttempts || time.Since(item.QueuedAt) >= maxAge {
		os.RemoveAll(entryDir)
		result.GaveUp++
		return
	}

	if updated, err := json.Marshal(item); err == nil {
		os.WriteFile(itemPath, updated, 0o644)
	}
	result.Pending++
}

// StartRetryWatcher periodically drains queueDir - only meaningful in
// "serve" mode, the only long-running scanner process; "scan"/"menu" only
// ever drain once, opportunistically, at the very start of their single
// run. Blocks until ctx is done. onResult is called after every tick
// (even an empty one) so the caller can log via its own mechanism -
// DrainResult.Empty() lets it skip logging a line for the common
// nothing-to-do case.
func StartRetryWatcher(ctx context.Context, queueDir string, c *client.Client, interval time.Duration, onResult func(DrainResult)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			onResult(Drain(ctx, queueDir, c))
		}
	}
}
