// Package progress buffers a scan's recent onProgress messages and
// periodically pushes a snapshot to the webserver, so the dashboard's
// "Details" popup on a running scan can show something close to a live
// tail without the webserver ever needing to reach back into the scanner
// (all communication here is scanner-initiated, same as everything else -
// see CLAUDE.md's "Why two separate services" - the webserver can't dial
// into a scanner that may be behind NAT/a firewall). This is a genuinely
// new, separate thing from internal/api/state.go's scanState: that one
// backs the scanner's own local "serve" REST API (queried locally, e.g.
// by a future scanner-side UI), this one feeds the webserver instead, and
// the two run independently even when both are active at once (serve mode
// does exactly that) rather than sharing a buffer.
package progress

import (
	"context"
	"sync"
	"time"
)

// LogLine mirrors the shape the webserver's ingest endpoint expects
// (server/src/db/types.ts's ScanProgressLogLine) - kept as a plain struct
// here rather than importing anything from the webserver side, since the
// two are only related by this JSON shape, not by any shared Go code.
type LogLine struct {
	Time    string `json:"time"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

// maxLogLines matches internal/api/state.go's own cap - not shared code,
// but there's no reason for the two buffers to disagree on how much
// recent history is worth keeping.
const maxLogLines = 100

// DefaultPushInterval is used by all three entry points (scan/menu/serve)
// for consistency - frequent enough that a "Details" popup open on the
// dashboard feels close to live, infrequent enough not to meaningfully
// add to the request volume a scan already generates (per-host
// submissions, excludes/probe-hostname fetches, etc).
const DefaultPushInterval = 3 * time.Second

// Pusher is the one method Tracker needs from client.Client - kept as an
// interface here (rather than importing the client package directly) so
// this package has no dependency on it at all, and so a test can supply a
// fake without spinning up a real HTTP client.
type Pusher interface {
	PushScanProgress(ctx context.Context, jobID, stage, detail string, logs []LogLine) error
}

// Tracker is safe for concurrent use - Progress is called from whichever
// pipeline goroutine is currently active (masscan, nmap, gowitness, RDP,
// TLS workers all log through the same onProgress callback, see
// orchestrator.go), while the background pusher goroutine reads the
// buffer on its own schedule.
type Tracker struct {
	pusher Pusher
	jobID  string

	mu     sync.Mutex
	stage  string
	detail string
	logs   []LogLine

	stop chan struct{}
	done chan struct{}
}

// NewTracker starts the periodic pusher immediately - call Close when the
// scan finishes (or fails) to stop it and flush one final snapshot, so
// the last thing the webserver has isn't up to `interval` stale.
func NewTracker(pusher Pusher, jobID string, interval time.Duration) *Tracker {
	t := &Tracker{
		pusher: pusher,
		jobID:  jobID,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go t.run(interval)
	return t
}

// Progress matches pipeline.ProgressFunc's signature exactly, so callers
// pass it directly (or wrap it alongside their own existing logging, as
// every one of the three entry points does) as RunScan's onProgress
// argument - no adapter needed.
func (t *Tracker) Progress(stage, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stage = stage
	t.detail = message
	t.logs = append(t.logs, LogLine{Time: time.Now().UTC().Format(time.RFC3339), Stage: stage, Message: message})
	if len(t.logs) > maxLogLines {
		t.logs = t.logs[len(t.logs)-maxLogLines:]
	}
}

func (t *Tracker) snapshot() (stage, detail string, logs []LogLine) {
	t.mu.Lock()
	defer t.mu.Unlock()
	logsCopy := make([]LogLine, len(t.logs))
	copy(logsCopy, t.logs)
	return t.stage, t.detail, logsCopy
}

func (t *Tracker) run(interval time.Duration) {
	defer close(t.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.push()
		case <-t.stop:
			// One last push so whatever the final state was (e.g. "submitting
			// host N of M") isn't lost to the last `interval` of silence -
			// the caller is about to mark the job completed/failed/cancelled
			// right after Close returns, so this is the last chance.
			t.push()
			return
		}
	}
}

func (t *Tracker) push() {
	stage, detail, logs := t.snapshot()
	if stage == "" {
		// Nothing recorded yet (e.g. the very first tick landing before any
		// onProgress call at all) - nothing worth sending.
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Best-effort, like every other progress-reporting call in this
	// codebase (onProgress itself only logs locally on failure elsewhere) -
	// a missed push just means the webserver's view is one interval
	// staler, not a reason to interrupt the scan itself.
	_ = t.pusher.PushScanProgress(ctx, t.jobID, stage, detail, logs)
}

// Close stops the periodic pusher and blocks until its final push
// completes (bounded by push's own 10s timeout, so this can't hang
// forever even if the webserver is unreachable).
func (t *Tracker) Close() {
	close(t.stop)
	<-t.done
}
