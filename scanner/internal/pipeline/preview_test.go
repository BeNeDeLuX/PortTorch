package pipeline

import "testing"

func TestPreviewScanPortExcludes(t *testing.T) {
	result, err := PreviewScan("10.0.0.0/24", "1-100", Excludes{Ports: []string{"80", "22"}})
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if result.EffectivePortSpec == "" {
		t.Fatal("expected a non-empty effective port spec")
	}
	// Confirm the excluded ports are actually gone and a non-excluded one
	// survives, without hardcoding the exact serialized range format.
	excludedSet, err := parsePortSet(result.EffectivePortSpec)
	if err != nil {
		t.Fatalf("parsing effective port spec %q: %v", result.EffectivePortSpec, err)
	}
	if _, ok := excludedSet[80]; ok {
		t.Error("expected port 80 to be excluded from the effective spec")
	}
	if _, ok := excludedSet[22]; ok {
		t.Error("expected port 22 to be excluded from the effective spec")
	}
	if _, ok := excludedSet[21]; !ok {
		t.Error("expected port 21 (not excluded, within 1-100) to remain in the effective spec")
	}
}

func TestPreviewScanAllPortsExcluded(t *testing.T) {
	result, err := PreviewScan("10.0.0.0/24", "80", Excludes{Ports: []string{"80"}})
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if result.EffectivePortSpec != "" {
		t.Errorf("expected an empty effective port spec when every requested port is excluded, got %q", result.EffectivePortSpec)
	}
}

func TestPreviewScanIPv4CIDRTarget(t *testing.T) {
	excludes := Excludes{IPs: []string{"10.0.0.5", "10.0.1.0/24"}}
	result, err := PreviewScan("10.0.0.0/16", "443", excludes)
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if result.IsIPv6 {
		t.Error("expected IsIPv6 to be false for an IPv4 CIDR target")
	}
	if result.SingleIPv4Target != nil {
		t.Errorf("expected no SingleIPv4Target for a CIDR, got %+v", result.SingleIPv4Target)
	}
	if len(result.AppliedIPExcludes) != 2 {
		t.Errorf("expected the applied IP excludes to be passed through unchanged, got %v", result.AppliedIPExcludes)
	}
}

func TestPreviewScanSingleIPv4TargetExcluded(t *testing.T) {
	excludes := Excludes{IPs: []string{"10.0.0.0/24"}}
	result, err := PreviewScan("10.0.0.5", "443", excludes)
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if result.SingleIPv4Target == nil {
		t.Fatal("expected a SingleIPv4Target for a bare IPv4 address")
	}
	if !result.SingleIPv4Target.Excluded {
		t.Error("expected the single target to be reported as excluded")
	}
	if result.SingleIPv4Target.Reason != "10.0.0.0/24" {
		t.Errorf("expected the matching exclude entry as the reason, got %q", result.SingleIPv4Target.Reason)
	}
}

func TestPreviewScanSingleIPv4TargetNotExcluded(t *testing.T) {
	excludes := Excludes{IPs: []string{"10.0.0.0/24"}}
	result, err := PreviewScan("192.168.1.5", "443", excludes)
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if result.SingleIPv4Target == nil {
		t.Fatal("expected a SingleIPv4Target for a bare IPv4 address")
	}
	if result.SingleIPv4Target.Excluded {
		t.Error("expected the single target to not be excluded")
	}
}

func TestPreviewScanIPv6Targets(t *testing.T) {
	excludes := Excludes{IPs: []string{"2001:db8::1"}}
	result, err := PreviewScan("2001:db8::1,2001:db8::2", "443", excludes)
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if !result.IsIPv6 {
		t.Fatal("expected IsIPv6 to be true")
	}
	if len(result.IPv6Targets) != 2 {
		t.Fatalf("expected 2 IPv6 targets, got %d", len(result.IPv6Targets))
	}
	if !result.IPv6Targets[0].Excluded {
		t.Error("expected 2001:db8::1 to be excluded")
	}
	if result.IPv6Targets[1].Excluded {
		t.Error("expected 2001:db8::2 to not be excluded")
	}
	if result.SingleIPv4Target != nil || len(result.AppliedIPExcludes) != 0 {
		t.Error("IPv4-specific fields should stay empty for an IPv6 target")
	}
}

func TestPreviewScanIPPortExcludesListed(t *testing.T) {
	excludes := Excludes{IPPorts: []IPPortExclude{{IP: "10.0.0.5", PortSpec: "3389"}}}
	result, err := PreviewScan("10.0.0.0/24", "1-1000", excludes)
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if len(result.IPPortExcludes) != 1 || result.IPPortExcludes[0] != "10.0.0.5:3389" {
		t.Errorf("expected one formatted ip:port exclude, got %v", result.IPPortExcludes)
	}
}

func TestPreviewScanInvalidPortSpec(t *testing.T) {
	if _, err := PreviewScan("10.0.0.0/24", "not-a-port", Excludes{}); err == nil {
		t.Fatal("expected an error for an invalid port spec")
	}
}

func TestPreviewScanInvalidIPv6TargetList(t *testing.T) {
	// A CIDR isn't a valid IPv6 target - PreviewScan should surface the
	// same error parseIPv6TargetList would give a real scan.
	if _, err := PreviewScan("2001:db8::/32", "443", Excludes{}); err == nil {
		t.Fatal("expected an error for an IPv6 CIDR target")
	}
}
