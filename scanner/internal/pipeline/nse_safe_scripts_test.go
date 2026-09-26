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

// The Default profile's size, pinned so an accidental addition or removal
// shows up as a failure rather than silently changing what every scan
// runs. 31 was the historical hardcoded list; the seven other
// *-ntlm-info scripts joined it for the exact Windows build and FQDN they
// report (see windowsversion.go), which nothing else on the list carries.
// Bumping this number is the deliberate act of extending the profile.
func TestDefaultNSEScriptsCount(t *testing.T) {
	if len(DefaultNSEScripts) != 38 {
		t.Errorf("DefaultNSEScripts count = %d, want 38 (31 historical + 7 *-ntlm-info)", len(DefaultNSEScripts))
	}
}

// A duplicate here is harmless to nmap, which is exactly why it would go
// unnoticed - it is evidence of a botched edit to the list, and the list
// is the one place a wrong entry breaks every host in a scan.
func TestDefaultNSEScriptsNoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(DefaultNSEScripts))
	for _, s := range DefaultNSEScripts {
		if seen[s] {
			t.Errorf("DefaultNSEScripts contains duplicate entry %q", s)
		}
		seen[s] = true
	}
}
