package pipeline

// Turning a symbolic profile name into the concrete script/tag lists
// RunScan takes. This lives here rather than next to either caller
// because both the queue loop (internal/api, resolving what the
// webserver sent) and the one-shot CLI/TUI (cmd/scanner, resolving what
// an operator typed) need the identical answer - and the whole point of
// the webserver sending a symbolic name instead of a 349-entry script
// list is that the canonical lists exist exactly once, in this package.
// Two copies of the mapping would reintroduce the drift that design
// avoids.

// ResolveNSEScripts turns a profile name plus an optional custom script
// list into the argument RunScan takes. Anything unrecognized - and the
// empty string, which is what a scan_requests row predating scan
// profiles carries - resolves to nil, which RunScan documents as "use
// DefaultNSEScripts". So an un-upgraded caller reproduces exactly the
// behaviour that existed before profiles did.
func ResolveNSEScripts(profile string, custom []string) []string {
	switch profile {
	case "all_safe":
		return AllSafeNSEScripts
	case "custom":
		return custom
	default:
		return nil
	}
}

// ResolveNucleiProfile is the nuclei equivalent. "off" (or any
// unrecognized/empty value - a pre-nuclei scan_requests row, or an older
// webserver that doesn't send this at all) resolves to nil, which
// RunScan documents as "nuclei doesn't run at all".
//
// "safe" is an *exclude* expression rather than an allowlist, unlike
// NSE's "all_safe": nuclei has no single stable safe category to point
// at - a real count against a freshly downloaded template tree returned
// 7625 distinct tags, growing with every release - so the honest way to
// express "safe" is to name what to keep out.
func ResolveNucleiProfile(profile string, tags []string) *NucleiProfile {
	switch profile {
	case "safe":
		return &NucleiProfile{ExcludeTags: []string{"dos", "fuzz", "intrusive"}}
	case "custom":
		return &NucleiProfile{Tags: tags}
	default:
		return nil
	}
}
