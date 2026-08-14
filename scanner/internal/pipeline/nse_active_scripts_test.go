package pipeline

import "testing"

func TestActiveNSEScriptsNoOverlapWithDefault(t *testing.T) {
	defaultSet := make(map[string]bool, len(DefaultNSEScripts))
	for _, s := range DefaultNSEScripts {
		defaultSet[s] = true
	}
	for name, list := range map[string][]string{
		"ExploitNSEScripts":        ExploitNSEScripts,
		"BruteNSEScripts":          BruteNSEScripts,
		"DosNSEScripts":            DosNSEScripts,
		"OtherIntrusiveNSEScripts": OtherIntrusiveNSEScripts,
	} {
		for _, s := range list {
			if defaultSet[s] {
				t.Errorf("%s contains %q, which is already in DefaultNSEScripts - should be excluded", name, s)
			}
		}
	}
}

func TestAllActiveNSEScriptsNoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(AllActiveNSEScripts))
	for _, s := range AllActiveNSEScripts {
		if seen[s] {
			t.Errorf("AllActiveNSEScripts contains duplicate entry %q", s)
		}
		seen[s] = true
	}
}

func TestAllActiveNSEScriptsIsUnionOfSubcategories(t *testing.T) {
	all := make(map[string]bool, len(AllActiveNSEScripts))
	for _, s := range AllActiveNSEScripts {
		all[s] = true
	}
	for name, list := range map[string][]string{
		"ExploitNSEScripts":        ExploitNSEScripts,
		"BruteNSEScripts":          BruteNSEScripts,
		"DosNSEScripts":            DosNSEScripts,
		"OtherIntrusiveNSEScripts": OtherIntrusiveNSEScripts,
	} {
		for _, s := range list {
			if !all[s] {
				t.Errorf("AllActiveNSEScripts is missing %q from %s", s, name)
			}
		}
	}
}
