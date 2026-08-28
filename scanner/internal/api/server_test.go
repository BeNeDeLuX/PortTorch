package api

import (
	"reflect"
	"testing"

	"porttorch/scanner/internal/pipeline"
)

func TestResolveNSEScripts(t *testing.T) {
	custom := []string{"http-title", "ssl-cert"}

	cases := []struct {
		name    string
		profile string
		custom  []string
		want    []string
	}{
		{"default", "default", nil, nil},
		{"empty profile (pre-migration/older webserver)", "", nil, nil},
		{"unrecognized profile", "something-else", custom, nil},
		{"all_safe", "all_safe", nil, pipeline.AllSafeNSEScripts},
		{"custom", "custom", custom, custom},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveNSEScripts(tc.profile, tc.custom)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolveNSEScripts(%q, %v) = %v, want %v", tc.profile, tc.custom, got, tc.want)
			}
		})
	}
}

func TestResolveNucleiProfile(t *testing.T) {
	custom := []string{"exposure", "cve"}

	cases := []struct {
		name    string
		profile string
		tags    []string
		want    *pipeline.NucleiProfile
	}{
		// "off" (or an empty/unrecognized value - a pre-nuclei scan_requests
		// row, or an older webserver that doesn't send this at all) must
		// resolve to nil - RunScan's own doc comment documents nil as
		// "nuclei never runs at all," so this is what makes every
		// pre-existing scan_requests row and every un-upgraded webserver
		// response reproduce exactly today's (pre-nuclei) behavior.
		{"off", "off", nil, nil},
		{"empty profile (pre-nuclei/older webserver)", "", nil, nil},
		{"unrecognized profile", "something-else", custom, nil},
		{"safe", "safe", nil, &pipeline.NucleiProfile{ExcludeTags: []string{"dos", "fuzz", "intrusive"}}},
		{"custom", "custom", custom, &pipeline.NucleiProfile{Tags: custom}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveNucleiProfile(tc.profile, tc.tags)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolveNucleiProfile(%q, %v) = %+v, want %+v", tc.profile, tc.tags, got, tc.want)
			}
		})
	}
}

// Dashboard-managed config overrides are applied in memory on top of the
// config loaded from disk. The behavior that's easy to get wrong is
// *removal*: clearing an override on the dashboard has to restore the
// file's value, not leave the last pushed one in place until a restart.
func TestApplyConfigOverrides(t *testing.T) {
	base := pipeline.Config{MasscanRate: 1000, Concurrency: 5, NucleiTimeoutSeconds: 300}

	cfg := base
	changed := applyConfigOverrides(&cfg, base, map[string]int{"masscanRate": 200, "concurrency": 12})
	if cfg.MasscanRate != 200 || cfg.Concurrency != 12 {
		t.Fatalf("overrides not applied: rate=%d concurrency=%d", cfg.MasscanRate, cfg.Concurrency)
	}
	if cfg.NucleiTimeoutSeconds != 300 {
		t.Fatalf("untouched setting changed: %d", cfg.NucleiTimeoutSeconds)
	}
	if len(changed) != 2 {
		t.Fatalf("changed = %v, want two entries", changed)
	}

	// Same overrides again: nothing actually changed, so nothing is
	// reported - otherwise every poll would log as if it had.
	changed = applyConfigOverrides(&cfg, base, map[string]int{"masscanRate": 200, "concurrency": 12})
	if len(changed) != 0 {
		t.Fatalf("changed = %v on a repeat poll, want empty", changed)
	}

	// Cleared on the dashboard - both must fall back to config.yaml.
	changed = applyConfigOverrides(&cfg, base, map[string]int{})
	if cfg.MasscanRate != 1000 || cfg.Concurrency != 5 {
		t.Fatalf("clearing did not restore the file's values: rate=%d concurrency=%d", cfg.MasscanRate, cfg.Concurrency)
	}
	if len(changed) != 2 {
		t.Fatalf("changed = %v after clearing, want both reported", changed)
	}
}

func TestApplyConfigOverridesIgnoresUnknownKeys(t *testing.T) {
	// A scanner older than a tunable added on the dashboard must keep
	// working rather than erroring on a key it doesn't know.
	base := pipeline.Config{MasscanRate: 1000}
	cfg := base
	changed := applyConfigOverrides(&cfg, base, map[string]int{"somethingNewer": 42, "masscanRate": 300})
	if cfg.MasscanRate != 300 {
		t.Fatalf("known key not applied alongside an unknown one: %d", cfg.MasscanRate)
	}
	if len(changed) != 1 {
		t.Fatalf("changed = %v, want only masscanRate", changed)
	}
}
