package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/pipeline"
)

type viewState int

const (
	viewTargetInput viewState = iota
	viewPortsInput
	viewConfirm
	viewCreatingJob
	viewRunning
	viewDone
	viewError
)

const maxLogLines = 15

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	labelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true)
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Italic(true)
)

type model struct {
	client   *client.Client
	pcfg     pipeline.Config
	queueDir string
	auditLog *auditlog.AuditLog

	state viewState

	targetInput textinput.Model
	portsInput  textinput.Model
	spinner     spinner.Model

	target string
	ports  string
	jobID  string

	progressCh chan progressMsg
	log        []string

	result           *pipeline.ScanResult
	errMsg           string
	screenshotErrors int
}

// New builds the initial Bubbletea model for the interactive scan menu.
func New(c *client.Client, pcfg pipeline.Config, queueDir string, auditLog *auditlog.AuditLog) model {
	ti := textinput.New()
	ti.Placeholder = "192.168.1.0/24 or 192.168.1.10"
	ti.Focus()
	ti.CharLimit = 128
	ti.Width = 40

	pi := textinput.New()
	pi.Placeholder = "1-1000 or 22,80,443"
	pi.CharLimit = 128
	pi.Width = 40

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = titleStyle

	return model{
		client:      c,
		pcfg:        pcfg,
		queueDir:    queueDir,
		auditLog:    auditLog,
		state:       viewTargetInput,
		targetInput: ti,
		portsInput:  pi,
		spinner:     sp,
	}
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}
		return m.handleKey(msg)

	case spinner.TickMsg:
		if m.state == viewRunning || m.state == viewCreatingJob {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case jobCreatedMsg:
		if msg.err != nil {
			m.state = viewError
			m.errMsg = fmt.Sprintf("Scan job could not be created: %v", msg.err)
			return m, nil
		}
		m.jobID = msg.jobID
		m.state = viewRunning
		m.progressCh = make(chan progressMsg, 32)
		m.log = []string{fmt.Sprintf("Scan job %s started", msg.jobID)}
		return m, tea.Batch(
			m.spinner.Tick,
			runScanCmd(m.client, m.pcfg, m.queueDir, m.auditLog, m.jobID, m.target, m.ports, m.progressCh),
			waitForProgress(m.progressCh),
		)

	case progressMsg:
		m.appendLog(fmt.Sprintf("[%s] %s", msg.stage, msg.message))
		return m, waitForProgress(m.progressCh)

	case scanDoneMsg:
		if msg.err != nil {
			m.state = viewError
			m.errMsg = fmt.Sprintf("Scan failed: %v", msg.err)
			return m, nil
		}
		m.result = msg.result
		m.screenshotErrors = msg.screenshotErrors
		m.state = viewDone
		return m, nil
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.state {
	case viewTargetInput:
		switch msg.String() {
		case "enter":
			val := strings.TrimSpace(m.targetInput.Value())
			if val == "" {
				return m, nil
			}
			m.target = val
			m.state = viewPortsInput
			m.portsInput.Focus()
			m.targetInput.Blur()
			return m, textinput.Blink
		case "esc", "q":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.targetInput, cmd = m.targetInput.Update(msg)
		return m, cmd

	case viewPortsInput:
		switch msg.String() {
		case "enter":
			val := strings.TrimSpace(m.portsInput.Value())
			if val == "" {
				return m, nil
			}
			m.ports = val
			m.state = viewConfirm
			return m, nil
		case "esc":
			m.state = viewTargetInput
			m.targetInput.Focus()
			m.portsInput.Blur()
			return m, textinput.Blink
		}
		var cmd tea.Cmd
		m.portsInput, cmd = m.portsInput.Update(msg)
		return m, cmd

	case viewConfirm:
		switch msg.String() {
		case "enter":
			m.state = viewCreatingJob
			return m, tea.Batch(m.spinner.Tick, createScanJobCmd(m.client, m.target, m.ports))
		case "esc":
			m.state = viewPortsInput
			return m, nil
		case "q":
			return m, tea.Quit
		}
		return m, nil

	case viewDone, viewError:
		switch msg.String() {
		case "n":
			return m.reset(), textinput.Blink
		case "q", "esc":
			return m, tea.Quit
		}
		return m, nil
	}

	return m, nil
}

func (m model) reset() model {
	fresh := New(m.client, m.pcfg, m.queueDir, m.auditLog)
	return fresh
}

func (m *model) appendLog(line string) {
	m.log = append(m.log, line)
	if len(m.log) > maxLogLines {
		m.log = m.log[len(m.log)-maxLogLines:]
	}
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("PortTorch Scanner") + "\n\n")

	switch m.state {
	case viewTargetInput:
		b.WriteString(labelStyle.Render("Target (IPv4 IP/CIDR/range, or IPv6 address/comma-list):") + "\n")
		b.WriteString(m.targetInput.View() + "\n\n")
		b.WriteString(helpStyle.Render("Enter to confirm, Esc to quit"))

	case viewPortsInput:
		b.WriteString(labelStyle.Render("Target:") + " " + m.target + "\n\n")
		b.WriteString(labelStyle.Render("Ports (e.g. 1-1000 or 22,80,443):") + "\n")
		b.WriteString(m.portsInput.View() + "\n\n")
		b.WriteString(helpStyle.Render("Enter to confirm, Esc to go back"))

	case viewConfirm:
		b.WriteString(labelStyle.Render("Target:") + " " + m.target + "\n")
		b.WriteString(labelStyle.Render("Ports:") + " " + m.ports + "\n\n")
		b.WriteString(helpStyle.Render("Enter to start, Esc to go back, q to quit"))

	case viewCreatingJob:
		b.WriteString(m.spinner.View() + " Creating scan job on the webserver...")

	case viewRunning:
		b.WriteString(m.spinner.View() + fmt.Sprintf(" Scan running (job %s)...\n\n", m.jobID))
		b.WriteString(dimStyle.Render(strings.Join(m.log, "\n")))

	case viewDone:
		hosts := 0
		ports := 0
		shots := 0
		rdpShots := 0
		if m.result != nil {
			hosts = len(m.result.Hosts)
			for _, h := range m.result.Hosts {
				ports += len(h.Ports)
				shots += len(h.Screenshots)
				rdpShots += len(h.RDPScreenshots)
			}
		}
		b.WriteString(successStyle.Render("Scan completed") + "\n\n")
		b.WriteString(fmt.Sprintf(
			"%d host(s), %d open port(s), %d screenshot(s), %d RDP screenshot(s) submitted.\n",
			hosts, ports, shots, rdpShots,
		))
		if m.screenshotErrors > 0 {
			b.WriteString(errorStyle.Render(fmt.Sprintf("%d screenshot(s) could not be submitted.\n", m.screenshotErrors)))
		}
		b.WriteString("\n" + helpStyle.Render("n = new scan, q = quit"))

	case viewError:
		b.WriteString(errorStyle.Render("Error") + "\n\n")
		b.WriteString(m.errMsg + "\n\n")
		b.WriteString(helpStyle.Render("n = new scan, q = quit"))
	}

	return b.String() + "\n"
}
