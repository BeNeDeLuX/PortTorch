package pipeline

import (
	"os"
	"path/filepath"
)

// CleanupScreenshots removes the temporary directories of all screenshots
// belonging to a scan result. Should be called by the caller after the
// screenshots have been (attempted to be) submitted to the ingest API.
func CleanupScreenshots(hosts []HostResult) {
	for _, h := range hosts {
		for _, s := range h.Screenshots {
			os.RemoveAll(filepath.Dir(s.ImagePath))
		}
		for _, s := range h.RDPScreenshots {
			os.RemoveAll(filepath.Dir(s.ImagePath))
		}
	}
}
