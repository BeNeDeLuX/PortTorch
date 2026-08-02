package api

import (
	"sync"

	"porttorch/scanner/internal/pipeline"
)

// scanStateView is the lock-free, JSON-serializable snapshot of a
// scanState. Kept as its own type so scanState (with its mutex) is never
// accidentally copied by value.
type scanStateView struct {
	Status         string   `json:"status"`
	TargetSpec     string   `json:"targetSpec"`
	PortSpec       string   `json:"portSpec"`
	Log            []string `json:"log"`
	HostsFound     int      `json:"hostsFound"`
	OpenPorts      int      `json:"openPorts"`
	Screenshots    int      `json:"screenshots"`
	RDPScreenshots int      `json:"rdpScreenshots"`
	Error          string   `json:"error,omitempty"`
}

type scanState struct {
	mu sync.Mutex

	view scanStateView
}

const maxLogLines = 100

func newScanState(target, ports string) *scanState {
	return &scanState{view: scanStateView{Status: "running", TargetSpec: target, PortSpec: ports}}
}

func (s *scanState) appendLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Log = append(s.view.Log, line)
	if len(s.view.Log) > maxLogLines {
		s.view.Log = s.view.Log[len(s.view.Log)-maxLogLines:]
	}
}

func (s *scanState) setFailed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Status = "failed"
	s.view.Error = err.Error()
}

func (s *scanState) setCancelled() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Status = "cancelled"
}

func (s *scanState) setCompleted(result *pipeline.ScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Status = "completed"
	s.view.HostsFound = len(result.Hosts)
	for _, h := range result.Hosts {
		s.view.OpenPorts += len(h.Ports)
		s.view.Screenshots += len(h.Screenshots)
		s.view.RDPScreenshots += len(h.RDPScreenshots)
	}
}

// snapshot returns a copy that can be safely used outside the lock (e.g.
// for JSON serialization).
func (s *scanState) snapshot() scanStateView {
	s.mu.Lock()
	defer s.mu.Unlock()
	logCopy := make([]string, len(s.view.Log))
	copy(logCopy, s.view.Log)
	v := s.view
	v.Log = logCopy
	return v
}
