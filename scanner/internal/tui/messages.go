package tui

import "porttorch/scanner/internal/pipeline"

// progressMsg carries a single progress message from the pipeline
// (masscan/nmap stage) into the Bubbletea event loop.
type progressMsg struct {
	stage   string
	message string
}

// jobCreatedMsg is delivered once the scan job has been created on the
// webserver (or creation has failed).
type jobCreatedMsg struct {
	jobID string
	err   error
}

// scanDoneMsg is delivered once the scan (and, since each host is
// submitted as soon as its own pipeline finishes rather than in one
// batch at the very end, its submission too) has fully finished.
type scanDoneMsg struct {
	result           *pipeline.ScanResult
	err              error
	screenshotErrors int
}
