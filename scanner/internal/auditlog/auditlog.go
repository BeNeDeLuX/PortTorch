// Package auditlog keeps a permanent, append-only, scanner-local record
// of every host result this scanner has ever found - independent of the
// webserver's own reachability or retention.
//
// Distinct from internal/submitqueue, which exists to recover from a
// TRANSIENT outage (it durably queues a failed submission and deletes the
// entry once resubmission succeeds, or gives up after 10 attempts/7
// days): this package logs every host unconditionally, submitted or not,
// and never removes an entry - the same "preserve history rather than
// hard-delete" philosophy the webserver's own audit_log table follows for
// exactly the same reason (a compliance/forensic trail that outlives
// whatever else may have gone wrong). If the webserver is unreachable for
// longer than the submit queue's own bounds, or a scanner_agent is later
// deleted and its scan_jobs history goes with it, this file on the
// scanner's own disk is still there.
package auditlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"porttorch/scanner/internal/pipeline"
)

// Entry is one line of the audit log - a compact summary, not the full
// host result (banners/CPEs/screenshots stay in the real submission
// only; duplicating all of that here would make this file grow far
// faster for comparatively little forensic value beyond "what was found,
// when, and was it confirmed delivered").
type Entry struct {
	Time      time.Time `json:"time"`
	ScanJobID string    `json:"scanJobId"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname,omitempty"`
	// Ports is "port/protocol" for every open port (e.g. "443/tcp"), not
	// the full PortResult - see the type doc comment on why this stays a
	// summary.
	Ports []string `json:"ports"`
	// Submitted reflects the live submission attempt at the time this
	// entry was written - false means it was queued for retry (see
	// internal/submitqueue) or lost outright, so grepping this file for
	// "submitted":false surfaces exactly what isn't yet confirmed
	// delivered to the webserver.
	Submitted bool `json:"submitted"`
}

// EntryFromHost builds an Entry from a real pipeline.HostResult - shared
// by all three entry points (scan/menu/serve) so the "open ports only,
// port/protocol format" summarization can't drift between them.
func EntryFromHost(jobID string, host pipeline.HostResult, submitted bool) Entry {
	ports := make([]string, 0, len(host.Ports))
	for _, p := range host.Ports {
		if p.State != "open" {
			continue
		}
		ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
	}
	return Entry{
		Time:      time.Now(),
		ScanJobID: jobID,
		IP:        host.IP,
		Hostname:  host.Hostname,
		Ports:     ports,
		Submitted: submitted,
	}
}

// AuditLog wraps the open file handle - a single instance is shared
// across every host write within one process (one scan for "scan"/"menu",
// every scan for the lifetime of a "serve" process), guarded by a mutex
// since hosts are written concurrently as they stream in from the
// pipeline's own worker pools.
type AuditLog struct {
	mu   sync.Mutex
	file *os.File
}

// Open opens (creating the file and any missing parent directories if
// needed) the audit log at path for appending. Never truncates or
// rewrites existing content - this file is meant to accumulate for the
// lifetime of the install.
func Open(path string) (*AuditLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	return &AuditLog{file: f}, nil
}

// Write appends one JSON line. A nil receiver is a safe no-op - lets
// every call site pass through whatever Open returned without a separate
// nil check at every write site (mirroring how a nil *log.Logger would
// panic, but a nil *AuditLog deliberately doesn't, since a failure to
// open this file must never be treated as fatal to an actual scan - see
// the callers in cmd/scanner and internal/api).
func (a *AuditLog) Write(entry Entry) error {
	if a == nil {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding audit log entry: %w", err)
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.file.Write(data); err != nil {
		return fmt.Errorf("writing audit log entry: %w", err)
	}
	return nil
}

// Close closes the underlying file. A nil receiver is a safe no-op, same
// reasoning as Write.
func (a *AuditLog) Close() error {
	if a == nil {
		return nil
	}
	return a.file.Close()
}

// ReadSince returns entries written at or after `since`, oldest first,
// optionally only those whose submission failed. Reading is deliberately
// separate from the append-only writer above: the file is the one durable
// local record of what this scanner touched, and until this existed it
// could only be read with jq on the host, as root, because it lives
// beside a 0600 config in the service account's home.
//
// A line that doesn't parse is skipped rather than aborting the read.
// This file is appended to by a live process, so the last line can
// legitimately be a partial write caught mid-flush - refusing to show any
// history because of that would be exactly backwards.
func ReadSince(path string, since time.Time, onlyUnsubmitted bool) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No scan has ever run on this host, which is an answer, not
			// an error.
			return nil, nil
		}
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	// A host with many ports produces a long line; the default 64KB token
	// limit would silently truncate the read at that point.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if !since.IsZero() && entry.Time.Before(since) {
			continue
		}
		if onlyUnsubmitted && entry.Submitted {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("reading audit log: %w", err)
	}
	return entries, nil
}
