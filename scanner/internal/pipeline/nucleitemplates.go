package pipeline

import (
	"os"
	"path/filepath"
	"time"
)

// nuclei's templates are fetched once by install.sh (`nuclei
// -update-templates`) and then never refreshed automatically - a
// deliberate choice, since a security scanner pulling new check logic
// from the internet unattended is a policy decision, not a technical
// default. The consequence is that they silently go stale: a scan with
// months-old templates looks exactly like a scan with current ones, it
// just quietly stops finding anything newer. Reporting when they were
// last updated is what makes that visible (see the webserver's Fleet
// Health "Nuclei Templates" card).
//
// Confirmed by real testing (see the root CLAUDE.md's nuclei section)
// that the tree lands in ~/nuclei-templates, not the ~/.config/nuclei/
// templates path nuclei's own docs suggest.
const defaultNucleiTemplatesDirName = "nuclei-templates"

// NucleiTemplatesUpdatedAt reports when the template tree at dir was last
// written, or the zero time if there's nothing there.
//
// Deliberately the directory's own mtime rather than parsing a file
// nuclei writes internally: `-update-templates` rewrites the tree, which
// touches the directory, and that holds regardless of nuclei's own
// on-disk bookkeeping format changing between versions. It's a heuristic
// - it moves if something else writes into the directory too - but for
// "are these templates roughly current or a year old" that's precise
// enough, and it can't break the way a parser tied to an undocumented
// internal file would.
func NucleiTemplatesUpdatedAt(dir string) (time.Time, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}, err
	}
	if !info.IsDir() {
		return time.Time{}, os.ErrNotExist
	}
	return info.ModTime(), nil
}

// DefaultNucleiTemplatesDir resolves the conventional location. Returns
// "" when the home directory can't be determined at all, which callers
// treat the same as "templates not found" - this is best-effort
// reporting, never something that should fail a scan.
func DefaultNucleiTemplatesDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, defaultNucleiTemplatesDirName)
}
