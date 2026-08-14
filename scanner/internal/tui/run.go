package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
)

// Run starts the interactive TUI menu. queueDir is where a failed
// submission is durably queued for retry - see internal/submitqueue.
func Run(c *client.Client, pcfg pipeline.Config, queueDir string) error {
	p := tea.NewProgram(New(c, pcfg, queueDir))
	_, err := p.Run()
	return err
}
