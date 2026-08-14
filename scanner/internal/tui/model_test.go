package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/pipeline"
)

func typeAndEnter(t *testing.T, m model, text string) model {
	t.Helper()
	for _, r := range text {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(model)
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return updated.(model)
}

func TestKeyboardNavigation(t *testing.T) {
	m := New(nil, pipeline.Config{}, "")
	if m.state != viewTargetInput {
		t.Fatalf("expected initial state viewTargetInput, got %v", m.state)
	}

	m = typeAndEnter(t, m, "192.168.1.0/24")
	if m.state != viewPortsInput {
		t.Fatalf("expected viewPortsInput after target entry, got %v", m.state)
	}
	if m.target != "192.168.1.0/24" {
		t.Fatalf("expected target to be captured, got %q", m.target)
	}

	// Esc goes one step back.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(model)
	if m.state != viewTargetInput {
		t.Fatalf("expected esc to go back to viewTargetInput, got %v", m.state)
	}

	m = typeAndEnter(t, m, "192.168.1.0/24")
	m = typeAndEnter(t, m, "1-1000")
	if m.state != viewConfirm {
		t.Fatalf("expected viewConfirm after ports entry, got %v", m.state)
	}
	if m.ports != "1-1000" {
		t.Fatalf("expected ports to be captured, got %q", m.ports)
	}
}

func TestCtrlCQuitsFromAnyState(t *testing.T) {
	states := []viewState{viewTargetInput, viewPortsInput, viewConfirm, viewRunning, viewDone, viewError}
	for _, st := range states {
		m := New(nil, pipeline.Config{}, "")
		m.state = st
		_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if cmd == nil {
			t.Fatalf("expected ctrl+c to return a quit cmd in state %v", st)
		}
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); !ok {
			t.Fatalf("expected tea.QuitMsg from ctrl+c in state %v, got %T", st, msg)
		}
	}
}

func TestAsyncFlowTransitions(t *testing.T) {
	m := New(nil, pipeline.Config{}, "")
	m.state = viewCreatingJob
	m.target = "10.0.0.5"
	m.ports = "80,443"

	// Job creation fails -> viewError.
	updated, _ := m.Update(jobCreatedMsg{err: errTest("boom")})
	m2 := updated.(model)
	if m2.state != viewError {
		t.Fatalf("expected viewError after failed job creation, got %v", m2.state)
	}

	// Job creation succeeds -> viewRunning, progress channel set.
	updated, cmd := m.Update(jobCreatedMsg{jobID: "job-123"})
	m3 := updated.(model)
	if m3.state != viewRunning {
		t.Fatalf("expected viewRunning after successful job creation, got %v", m3.state)
	}
	if m3.jobID != "job-123" {
		t.Fatalf("expected jobID to be stored, got %q", m3.jobID)
	}
	if cmd == nil {
		t.Fatalf("expected a batched cmd after job creation")
	}

	// Progress message gets logged.
	updated, _ = m3.Update(progressMsg{stage: "masscan", message: "scanning"})
	m4 := updated.(model)
	if len(m4.log) == 0 {
		t.Fatalf("expected progress message to be appended to log")
	}

	// Scan fails -> viewError.
	updated, _ = m4.Update(scanDoneMsg{err: errTest("scan failed")})
	m5 := updated.(model)
	if m5.state != viewError {
		t.Fatalf("expected viewError after failed scan, got %v", m5.state)
	}

	// Scan (and its now-interleaved per-host submission) succeeds ->
	// viewDone directly - there's no separate "submitting" phase anymore
	// since each host is submitted as soon as its own pipeline finishes,
	// not batched into one step after the whole scan completes.
	result := &pipeline.ScanResult{Hosts: []pipeline.HostResult{{IP: "10.0.0.5"}}}
	updated, _ = m4.Update(scanDoneMsg{result: result})
	m6 := updated.(model)
	if m6.state != viewDone {
		t.Fatalf("expected viewDone after successful scan, got %v", m6.state)
	}

	// "n" on viewDone resets the model.
	updated, _ = m6.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	m8 := updated.(model)
	if m8.state != viewTargetInput {
		t.Fatalf("expected reset to viewTargetInput, got %v", m8.state)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
