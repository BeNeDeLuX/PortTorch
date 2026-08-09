package progress

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakePusher struct {
	mu        sync.Mutex
	calls     []pushCall
	fullCalls []fullLogPushCall
}

type pushCall struct {
	jobID, stage, detail string
	logs                 []LogLine
}

type fullLogPushCall struct {
	jobID string
	logs  []LogLine
}

func (f *fakePusher) PushScanProgress(_ context.Context, jobID, stage, detail string, logs []LogLine) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	logsCopy := make([]LogLine, len(logs))
	copy(logsCopy, logs)
	f.calls = append(f.calls, pushCall{jobID: jobID, stage: stage, detail: detail, logs: logsCopy})
	return nil
}

func (f *fakePusher) PushFullScanLog(_ context.Context, jobID string, logs []LogLine) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	logsCopy := make([]LogLine, len(logs))
	copy(logsCopy, logs)
	f.fullCalls = append(f.fullCalls, fullLogPushCall{jobID: jobID, logs: logsCopy})
	return nil
}

func (f *fakePusher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePusher) lastCall() pushCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fakePusher) fullLogCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fullCalls)
}

func (f *fakePusher) lastFullLogCall() fullLogPushCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fullCalls[len(f.fullCalls)-1]
}

func TestTrackerBuffersLogLinesAndCapsAtMax(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-1", time.Hour) // long interval - only Close's final push fires
	for i := 0; i < maxLogLines+20; i++ {
		tr.Progress("nmap", "line")
	}
	tr.Close()

	if pusher.callCount() != 1 {
		t.Fatalf("expected exactly 1 push (from Close), got %d", pusher.callCount())
	}
	call := pusher.lastCall()
	if len(call.logs) != maxLogLines {
		t.Fatalf("expected buffer capped at %d lines, got %d", maxLogLines, len(call.logs))
	}
}

func TestTrackerPushesLatestStageAndDetail(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-2", time.Hour)
	tr.Progress("masscan", "scanning 10.0.0.0/24")
	tr.Progress("nmap", "probing 10.0.0.5")
	tr.Close()

	call := pusher.lastCall()
	if call.jobID != "job-2" {
		t.Errorf("jobID = %q, want job-2", call.jobID)
	}
	if call.stage != "nmap" {
		t.Errorf("stage = %q, want the most recent stage (nmap)", call.stage)
	}
	if call.detail != "probing 10.0.0.5" {
		t.Errorf("detail = %q, want the most recent message", call.detail)
	}
	if len(call.logs) != 2 || call.logs[0].Stage != "masscan" || call.logs[1].Stage != "nmap" {
		t.Errorf("logs = %+v, want both lines in order", call.logs)
	}
}

func TestTrackerPushesNothingBeforeFirstProgressCall(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-3", time.Hour)
	tr.Close() // final push fires, but stage is still "" - push() should skip it

	if pusher.callCount() != 0 {
		t.Fatalf("expected no push when Progress was never called, got %d", pusher.callCount())
	}
	if pusher.fullLogCallCount() != 0 {
		t.Fatalf("expected no full-log push when Progress was never called, got %d", pusher.fullLogCallCount())
	}
}

func TestTrackerPushesFullLogOnceAtClose(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-5", time.Hour)
	tr.Progress("masscan", "scanning 10.0.0.0/24")
	tr.Progress("nmap", "probing 10.0.0.5")
	tr.Progress("submit", "submitted 10.0.0.5 (3 open port(s))")

	if pusher.fullLogCallCount() != 0 {
		t.Fatalf("expected no full-log push before Close, got %d", pusher.fullLogCallCount())
	}

	tr.Close()

	if pusher.fullLogCallCount() != 1 {
		t.Fatalf("expected exactly 1 full-log push (from Close), got %d", pusher.fullLogCallCount())
	}
	call := pusher.lastFullLogCall()
	if call.jobID != "job-5" {
		t.Errorf("jobID = %q, want job-5", call.jobID)
	}
	if len(call.logs) != 3 || call.logs[0].Stage != "masscan" || call.logs[2].Stage != "submit" {
		t.Errorf("logs = %+v, want all 3 lines in order", call.logs)
	}
}

func TestTrackerFullLogSurvivesPastMaxLogLinesButCapsAtMaxFullLogLines(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-6", time.Hour)
	// More than maxLogLines (the periodic-push cap) but well under
	// maxFullLogLines - the full log must keep everything here, unlike
	// the capped periodic snapshot which would have trimmed it.
	total := maxLogLines + 50
	for i := 0; i < total; i++ {
		tr.Progress("nmap", "line")
	}
	tr.Close()

	call := pusher.lastFullLogCall()
	if len(call.logs) != total {
		t.Fatalf("expected full log to keep all %d lines (not capped at maxLogLines=%d), got %d", total, maxLogLines, len(call.logs))
	}

	// And the periodic-push cap is still enforced independently.
	if len(pusher.lastCall().logs) != maxLogLines {
		t.Fatalf("expected periodic push still capped at %d lines, got %d", maxLogLines, len(pusher.lastCall().logs))
	}
}

func TestTrackerFullLogCapsAtMaxFullLogLines(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-7", time.Hour)
	total := maxFullLogLines + 20
	for i := 0; i < total; i++ {
		tr.Progress("nmap", "line")
	}
	tr.Close()

	call := pusher.lastFullLogCall()
	if len(call.logs) != maxFullLogLines {
		t.Fatalf("expected full log capped at %d lines, got %d", maxFullLogLines, len(call.logs))
	}
}

func TestTrackerPushesPeriodically(t *testing.T) {
	pusher := &fakePusher{}
	tr := NewTracker(pusher, "job-4", 20*time.Millisecond)
	tr.Progress("masscan", "scanning")

	deadline := time.Now().Add(2 * time.Second)
	for pusher.callCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	tr.Close()

	if pusher.callCount() < 2 {
		t.Fatalf("expected at least 2 periodic pushes within the deadline, got %d", pusher.callCount())
	}
}
