package main

import (
	"path/filepath"
	"testing"
)

// The case this exists for: an admin runs `sudo porttorch doctor
// --config /var/lib/porttorch/.config/porttorch/config.yaml` and used to
// be told the templates were missing, because it looked in root's home
// while the service reads its own.
func TestNucleiTemplatesDirForConfig(t *testing.T) {
	got := nucleiTemplatesDirForConfig("/var/lib/porttorch/.config/porttorch/config.yaml")
	if want := filepath.FromSlash("/var/lib/porttorch/nuclei-templates"); got != want {
		t.Errorf("service config path resolved to %q, want %q", got, want)
	}

	// A config that isn't under a ".config" directory says nothing about
	// any other user's home, so the invoking user's own is the only
	// answer - signalled by an empty string rather than a guess.
	if got := nucleiTemplatesDirForConfig("/etc/porttorch/config.yaml"); got != "" {
		t.Errorf("standalone config path resolved to %q, want empty", got)
	}
}
