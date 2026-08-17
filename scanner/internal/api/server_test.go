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
