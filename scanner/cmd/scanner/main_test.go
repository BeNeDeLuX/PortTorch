package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTargetsFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing targets file: %v", err)
	}
	return path
}

func TestParseTargetsFileJoinsWithCommas(t *testing.T) {
	path := writeTargetsFile(t, "10.0.0.0/24\n192.168.1.5\n10.0.5.1-10.0.5.50\n")
	got, err := parseTargetsFile(path)
	if err != nil {
		t.Fatalf("parseTargetsFile: %v", err)
	}
	want := "10.0.0.0/24,192.168.1.5,10.0.5.1-10.0.5.50"
	if got != want {
		t.Errorf("parseTargetsFile() = %q, want %q", got, want)
	}
}

func TestParseTargetsFileSkipsBlankLinesAndComments(t *testing.T) {
	path := writeTargetsFile(t, "# office subnet\n10.0.0.0/24\n\n   \n# datacenter\n10.0.1.0/24\n")
	got, err := parseTargetsFile(path)
	if err != nil {
		t.Fatalf("parseTargetsFile: %v", err)
	}
	want := "10.0.0.0/24,10.0.1.0/24"
	if got != want {
		t.Errorf("parseTargetsFile() = %q, want %q", got, want)
	}
}

func TestParseTargetsFileTrimsWhitespace(t *testing.T) {
	path := writeTargetsFile(t, "  10.0.0.0/24  \n\t10.0.1.5\t\n")
	got, err := parseTargetsFile(path)
	if err != nil {
		t.Fatalf("parseTargetsFile: %v", err)
	}
	want := "10.0.0.0/24,10.0.1.5"
	if got != want {
		t.Errorf("parseTargetsFile() = %q, want %q", got, want)
	}
}

func TestParseTargetsFileIPv6Addresses(t *testing.T) {
	path := writeTargetsFile(t, "2001:db8::1\n2001:db8::2\n")
	got, err := parseTargetsFile(path)
	if err != nil {
		t.Fatalf("parseTargetsFile: %v", err)
	}
	want := "2001:db8::1,2001:db8::2"
	if got != want {
		t.Errorf("parseTargetsFile() = %q, want %q", got, want)
	}
}

func TestParseTargetsFileEmptyIsAnError(t *testing.T) {
	path := writeTargetsFile(t, "# nothing but comments\n\n")
	if _, err := parseTargetsFile(path); err == nil {
		t.Fatal("expected an error for a targets file with no actual targets")
	}
}

func TestParseTargetsFileMissingFileIsAnError(t *testing.T) {
	if _, err := parseTargetsFile(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error for a nonexistent targets file")
	}
}
