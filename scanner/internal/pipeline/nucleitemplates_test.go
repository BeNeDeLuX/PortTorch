package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real filesystem, no mocks - the whole function is a stat call, so
// stubbing it would only test the stub.
func TestNucleiTemplatesUpdatedAtReportsDirectoryMtime(t *testing.T) {
	dir := t.TempDir()
	want := time.Now().Add(-90 * 24 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(dir, want, want); err != nil {
		t.Fatalf("setting mtime: %v", err)
	}

	got, err := NucleiTemplatesUpdatedAt(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("NucleiTemplatesUpdatedAt = %v, want %v", got, want)
	}
}

func TestNucleiTemplatesUpdatedAtMissingDirectory(t *testing.T) {
	_, err := NucleiTemplatesUpdatedAt(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected an error for a missing templates directory, got nil")
	}
}

// A file where a directory is expected is a real possibility (a partial
// or interrupted install), and must not be reported as a valid template
// tree with whatever mtime that file happens to carry.
func TestNucleiTemplatesUpdatedAtRejectsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nuclei-templates")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if _, err := NucleiTemplatesUpdatedAt(path); err == nil {
		t.Fatal("expected an error when the path is a file, got nil")
	}
}

func TestDefaultNucleiTemplatesDirUsesHome(t *testing.T) {
	dir := DefaultNucleiTemplatesDir()
	if dir == "" {
		t.Skip("no home directory resolvable in this environment")
	}
	if filepath.Base(dir) != "nuclei-templates" {
		t.Errorf("DefaultNucleiTemplatesDir = %q, want it to end in nuclei-templates", dir)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("DefaultNucleiTemplatesDir = %q, want an absolute path", dir)
	}
}
