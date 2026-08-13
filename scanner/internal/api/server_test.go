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
