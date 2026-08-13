package pipeline

import "testing"

func TestAllSafeNSEScriptsSupersetOfDefault(t *testing.T) {
	all := make(map[string]bool, len(AllSafeNSEScripts))
	for _, s := range AllSafeNSEScripts {
		all[s] = true
	}
	for _, s := range DefaultNSEScripts {
		if !all[s] {
			t.Errorf("AllSafeNSEScripts is missing Default script %q - switching profiles must never drop a script", s)
		}
	}
}

func TestAllSafeNSEScriptsNoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(AllSafeNSEScripts))
	for _, s := range AllSafeNSEScripts {
		if seen[s] {
			t.Errorf("AllSafeNSEScripts contains duplicate entry %q", s)
		}
		seen[s] = true
	}
}

func TestDefaultNSEScriptsCount(t *testing.T) {
	if len(DefaultNSEScripts) != 31 {
		t.Errorf("DefaultNSEScripts count = %d, want 31 (the historical hardcoded list)", len(DefaultNSEScripts))
	}
}
