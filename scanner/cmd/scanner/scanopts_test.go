package main

import (
	"strings"
	"testing"

	"porttorch/scanner/internal/pipeline"
)

// These flags exist to close the gap between what the dashboard could ask
// for and what the CLI could - so the thing worth pinning is that the
// default invocation still resolves to exactly what it did before they
// existed, and that a typo is refused rather than silently downgraded.
func TestScanOptionsDefaultsAreUnchangedBehaviour(t *testing.T) {
	nse, nuclei, rate, err := scanOptions{nseProfile: "default", nuclei: "off"}.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if nse != nil {
		t.Errorf("default profile must resolve to nil (RunScan's own DefaultNSEScripts), got %d scripts", len(nse))
	}
	if nuclei != nil {
		t.Error("nuclei must be off by default - it never ran from the CLI before these flags")
	}
	if rate != nil {
		t.Error("no --rate means no override, so config.yaml decides")
	}

	// An empty struct is what an invocation with no flags at all
	// produces; it must mean the same thing.
	nse2, nuclei2, rate2, err := scanOptions{}.resolve()
	if err != nil || nse2 != nil || nuclei2 != nil || rate2 != nil {
		t.Errorf("zero options must equal explicit defaults, got %v %v %v %v", nse2, nuclei2, rate2, err)
	}
}

func TestScanOptionsResolvesProfiles(t *testing.T) {
	nse, _, _, err := scanOptions{nseProfile: "all-safe"}.resolve()
	if err != nil {
		t.Fatalf("all-safe: %v", err)
	}
	if len(nse) != len(pipeline.AllSafeNSEScripts) {
		t.Errorf("all-safe resolved to %d scripts, want the package's own %d", len(nse), len(pipeline.AllSafeNSEScripts))
	}

	nse, _, _, err = scanOptions{nseProfile: "custom", nseScripts: "banner, ssh-hostkey ,,http-title"}.resolve()
	if err != nil {
		t.Fatalf("custom: %v", err)
	}
	if got := strings.Join(nse, ","); got != "banner,ssh-hostkey,http-title" {
		t.Errorf("custom scripts = %q, want the list trimmed with the empty entry dropped", got)
	}

	_, nuclei, _, err := scanOptions{nuclei: "safe"}.resolve()
	if err != nil {
		t.Fatalf("safe nuclei: %v", err)
	}
	if len(nuclei.ExcludeTags) != 3 {
		t.Errorf("safe must be an exclude expression, got %+v", nuclei)
	}

	_, nuclei, _, err = scanOptions{nuclei: "custom", nucleiTags: "cve,exposure"}.resolve()
	if err != nil {
		t.Fatalf("custom nuclei: %v", err)
	}
	if strings.Join(nuclei.Tags, ",") != "cve,exposure" {
		t.Errorf("custom tags = %v", nuclei.Tags)
	}

	_, _, rate, err := scanOptions{masscanRate: 250}.resolve()
	if err != nil || rate == nil || *rate != 250 {
		t.Errorf("rate = %v (err %v), want 250", rate, err)
	}
}

// A typo must not quietly run the default set - that is exactly the
// silent difference these flags exist to remove.
func TestScanOptionsRejectsUnknownAndIncompleteValues(t *testing.T) {
	for _, o := range []scanOptions{
		{nseProfile: "allsafe"},
		{nseProfile: "custom"},
		{nuclei: "on"},
		{nuclei: "custom"},
	} {
		if _, _, _, err := o.resolve(); err == nil {
			t.Errorf("resolve(%+v) succeeded, want an error", o)
		}
	}
}
