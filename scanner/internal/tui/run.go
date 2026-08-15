package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
)

// Run starts the interactive TUI menu. queueDir is where a failed
// submission is durably queued for retry - see internal/submitqueue.
// auditLog is the permanent local scan record (see internal/auditlog),
// shared across every scan run during this session; may be nil.
func Run(c *client.Client, pcfg pipeline.Config, queueDir string, auditLog *auditlog.AuditLog) error {
	p := tea.NewProgram(New(c, pcfg, queueDir, auditLog))
	_, err := p.Run()
	return err
}
