// Package logging provides a structured JSON logger for the
// non-interactive scanner modes ("scan", "serve"). Their stdout consists
// exclusively of one JSON line per event, so the log stream can be
// forwarded unchanged to a log shipper (Filebeat, Fluent Bit, Vector, ...)
// and from there to a SIEM. The interactive TUI menu ("menu")
// deliberately doesn't use this logger, since it takes over the entire
// terminal screen.
package logging

import (
	"log/slog"
	"os"
)

// New builds a JSON logger that writes to os.Stdout.
func New() *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(handler)
}
