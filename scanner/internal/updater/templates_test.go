package updater

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeTemplateClient struct {
	requested      bool
	requestedErr   error
	requestedCalls int
	outcomeCalls   int
	lastSucceeded  bool
	lastReason     string
	refreshCalls   int
}

func (f *fakeTemplateClient) CheckTemplateUpdateRequested(ctx context.Context) (bool, error) {
	f.requestedCalls++
	return f.requested, f.requestedErr
}

func (f *fakeTemplateClient) ReportTemplateUpdateOutcome(ctx context.Context, succeeded bool, reason string) error {
	f.outcomeCalls++
	f.lastSucceeded = succeeded
	f.lastReason = reason
	return nil
}

func (f *fakeTemplateClient) RefreshNucleiTemplatesUpdatedAt() { f.refreshCalls++ }

func failingRunner(t *testing.T) func(context.Context, string) (string, error) {
	return func(context.Context, string) (string, error) {
		t.Helper()
		t.Fatal("the template update should not have been run")
		return "", nil
	}
}

func TestCheckAndUpdateTemplates_NotRequested(t *testing.T) {
	c := &fakeTemplateClient{requested: false}
	checkAndUpdateTemplates(context.Background(), c, fakeBusy{}, "nuclei", discardLogger(), failingRunner(t))
	if c.outcomeCalls != 0 {
		t.Errorf("no outcome should be reported when nothing was requested, got %d calls", c.outcomeCalls)
	}
	if c.refreshCalls != 0 {
		t.Errorf("templates should not be re-stat'd when nothing was requested, got %d calls", c.refreshCalls)
	}
}

// Deferring rather than running mid-scan is the whole reason the watcher
// takes a BusyChecker - -update-templates rewrites the tree in place,
// which a concurrently-running nuclei is reading from.
func TestCheckAndUpdateTemplates_DefersWhileScanning(t *testing.T) {
	c := &fakeTemplateClient{requested: true}
	checkAndUpdateTemplates(context.Background(), c, fakeBusy{busy: true}, "nuclei", discardLogger(), failingRunner(t))
	if c.outcomeCalls != 0 {
		t.Errorf("a deferred update must not report any outcome yet, got %d calls", c.outcomeCalls)
	}
}

// A failed check must not be mistaken for "nothing requested" and must
// not report a failure outcome either - there's been no attempt to fail.
func TestCheckAndUpdateTemplates_CheckFailure(t *testing.T) {
	c := &fakeTemplateClient{requestedErr: errors.New("webserver unreachable")}
	checkAndUpdateTemplates(context.Background(), c, fakeBusy{}, "nuclei", discardLogger(), failingRunner(t))
	if c.outcomeCalls != 0 {
		t.Errorf("a failed check should report no outcome, got %d calls", c.outcomeCalls)
	}
}

func TestCheckAndUpdateTemplates_SuccessRefreshesBeforeReporting(t *testing.T) {
	c := &fakeTemplateClient{requested: true}
	checkAndUpdateTemplates(context.Background(), c, fakeBusy{}, "nuclei", discardLogger(),
		func(context.Context, string) (string, error) { return "templates updated", nil })

	if !c.lastSucceeded {
		t.Error("a successful run should report success")
	}
	if c.refreshCalls != 1 {
		t.Errorf("templates should be re-stat'd exactly once on success, got %d calls", c.refreshCalls)
	}
	if c.lastReason != "" {
		t.Errorf("a success carries no failure reason, got %q", c.lastReason)
	}
}

// The reason is what the admin actually sees on the Scanner Agents page,
// so nuclei's own output has to reach it - the bare exec error ("exit
// status 1") on its own says nothing about what went wrong.
func TestCheckAndUpdateTemplates_FailureIncludesToolOutput(t *testing.T) {
	c := &fakeTemplateClient{requested: true}
	checkAndUpdateTemplates(context.Background(), c, fakeBusy{}, "nuclei", discardLogger(),
		func(context.Context, string) (string, error) {
			return "could not read templates directory: permission denied", errors.New("exit status 1")
		})

	if c.lastSucceeded {
		t.Error("a failed run must report failure")
	}
	if !strings.Contains(c.lastReason, "permission denied") {
		t.Errorf("failure reason should carry nuclei's own output, got %q", c.lastReason)
	}
	if !strings.Contains(c.lastReason, "exit status 1") {
		t.Errorf("failure reason should also carry the exec error, got %q", c.lastReason)
	}
	if c.refreshCalls != 0 {
		t.Errorf("a failed update must not re-stat the templates as if they changed, got %d calls", c.refreshCalls)
	}
}

func TestTailOutput(t *testing.T) {
	if got := tailOutput("  short  ", 100); got != "short" {
		t.Errorf("tailOutput should trim and pass through short input, got %q", got)
	}

	// Cuts at a line boundary so a truncated reason doesn't begin
	// mid-word.
	long := strings.Repeat("noise\n", 200) + "the actual error"
	got := tailOutput(long, 50)
	if !strings.Contains(got, "the actual error") {
		t.Errorf("tailOutput should keep the tail, where the real error is, got %q", got)
	}
	if len(got) > 50 {
		t.Errorf("tailOutput should respect the cap, got %d bytes", len(got))
	}
	if strings.HasPrefix(got, "oise") {
		t.Errorf("tailOutput should cut at a line boundary, got %q", got)
	}
}
