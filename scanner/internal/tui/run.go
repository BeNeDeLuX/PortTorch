package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
)

// Run starts the interactive TUI menu.
func Run(c *client.Client, pcfg pipeline.Config) error {
	p := tea.NewProgram(New(c, pcfg))
	_, err := p.Run()
	return err
}
