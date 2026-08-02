package pipeline

import (
	"encoding/xml"
	"testing"
)

// TestParseSSHHostKeys uses the exact table structure that nmap's
// ssh-hostkey script returned live against a test SSH server (Debian
// Bullseye/OpenSSH 8.4, classic algorithms) - see the comment in nmap.go
// about the best-effort limitation against modern OpenSSH defaults.
func TestParseSSHHostKeys(t *testing.T) {
	tables := []nmapScriptTable{
		{Elems: []nmapScriptTableElem{
			{Key: "key", Value: "AAAAB3NzaC1yc2EAAAADAQABAAABgQDYI/39ZxvaZvypab9UjjRtG91UGhHRxU7V/y8FaHIoZFm3UzvK1Fmey1Ku2n4fZNvrYe2JVvM7n5UanQiAMows74j9X7KzUjhhAOlYMRmObqIWnWEY0Sx8AZkCW6YoPHDRRC0RnPfG1mUhoqCHh3Vulx4je5TYOSYLArQAhz8LI4t5mHCVr2QB18QQ+DVQGyiwqLL0qH+9QOScZFtIoes/WMJzX7nJrRuguhWKSTP670QWr8I4Q00WU2y4x1snaxd27QTjaYVDNa0JjlXLfRNgm5Qp7K35NLzXE8xPLDjehZ/MiKzD9SvijCVyyN9o2WxsNKcLO6lWlmIHS2x7op5Xl1CbAI2K11xAgE/eRA+sJpaX2xDJLg6P9Tzn0GF1CyVty0kx9YHp1UiXfnekbkokJFDUE2wH7JHk9mtObiXjkc5U1KGNBscDPhnGPd6FJnnGxPDhzYNDzt5YVVNPzb4RDwk2TdunOvS1WGF8nQIanKeEcAajWCk5mdUprwvq1H8="},
			{Key: "fingerprint", Value: "4b0685456bc6ef780b98b174e085a47f"},
			{Key: "bits", Value: "3072"},
			{Key: "type", Value: "ssh-rsa"},
		}},
		{Elems: []nmapScriptTableElem{
			{Key: "key", Value: "AAAAC3NzaC1lZDI1NTE5AAAAIBf4vUaexMNCJnNfARIFloGA+HnyPGVJCY5XcqXpB1Er"},
			{Key: "fingerprint", Value: "ee48bd52b6109ac19d7bb74437501176"},
			{Key: "bits", Value: "256"},
			{Key: "type", Value: "ssh-ed25519"},
		}},
	}

	keys := parseSSHHostKeys(tables)
	if len(keys) != 2 {
		t.Fatalf("expected 2 host keys, got %d", len(keys))
	}

	rsa := keys[0]
	if rsa.KeyType != "ssh-rsa" || rsa.Bits != 3072 || rsa.FingerprintMD5 != "4b0685456bc6ef780b98b174e085a47f" {
		t.Errorf("unexpected rsa key: %+v", rsa)
	}
	if rsa.FingerprintSHA256 == "" || rsa.FingerprintSHA256[:7] != "SHA256:" {
		t.Errorf("expected a SHA256: prefixed fingerprint, got %q", rsa.FingerprintSHA256)
	}

	ed25519 := keys[1]
	// Known value, independently recomputed with ssh-keygen -lf for this
	// specific test key, to cover the fingerprint calculation (not just
	// the parsing).
	const wantFingerprint = "SHA256:OK/6boqyzD/VTf4mjURVibvIZTY15RqqA90H0e5kKwY"
	if ed25519.FingerprintSHA256 != wantFingerprint {
		t.Errorf("fingerprint = %q, want %q", ed25519.FingerprintSHA256, wantFingerprint)
	}
}

// TestApplyBestOSMatch uses the exact osmatch/osclass structure nmap -O
// returned live against this machine (run as root; -O requires it, see
// the comment in nmap.go) - two matches tied at accuracy 97, nmap's own
// ordering (best guess first) decides the winner, not a re-sort here.
func TestApplyBestOSMatch(t *testing.T) {
	matches := []nmapOSMatch{
		{
			Name:     "Linux 2.6.32",
			Accuracy: "97",
			Classes: []nmapOSClass{
				{Type: "general purpose", Vendor: "Linux", OSFamily: "Linux", OSGen: "2.6.X", Accuracy: "97"},
			},
		},
		{
			Name:     "Linux 5.0 - 6.2",
			Accuracy: "97",
			Classes: []nmapOSClass{
				{Type: "general purpose", Vendor: "Linux", OSFamily: "Linux", OSGen: "5.X", Accuracy: "97"},
				{Type: "general purpose", Vendor: "Linux", OSFamily: "Linux", OSGen: "6.X", Accuracy: "97"},
			},
		},
	}

	result := &HostResult{}
	applyBestOSMatch(result, matches)

	if result.OSName != "Linux 2.6.32" {
		t.Errorf("OSName = %q, want the first (best-guess) match", result.OSName)
	}
	if result.OSAccuracy != 97 {
		t.Errorf("OSAccuracy = %d, want 97", result.OSAccuracy)
	}
	if result.OSFamily != "Linux" || result.OSVendor != "Linux" || result.DeviceType != "general purpose" {
		t.Errorf("unexpected classification: family=%q vendor=%q type=%q", result.OSFamily, result.OSVendor, result.DeviceType)
	}
}

func TestApplyBestOSMatchNoMatches(t *testing.T) {
	result := &HostResult{}
	applyBestOSMatch(result, nil)
	if result.OSName != "" || result.DeviceType != "" {
		t.Errorf("expected no changes for an empty match list, got %+v", result)
	}
}

func TestApplyMACAddress(t *testing.T) {
	// Real shape of nmap's XML: an ipv4 address always present, a mac
	// address only when nmap resolved the host via ARP (same local L2
	// segment) - confirmed against a real nmap run.
	addresses := []nmapAddress{
		{Addr: "172.16.60.252", AddrType: "ipv4"},
		{Addr: "BC:24:11:18:6A:68", AddrType: "mac", Vendor: "Proxmox Server Solutions GmbH"},
	}

	result := &HostResult{}
	applyMACAddress(result, addresses)

	if result.MACAddress != "BC:24:11:18:6A:68" {
		t.Errorf("MACAddress = %q, want the mac-typed address", result.MACAddress)
	}
	if result.MACVendor != "Proxmox Server Solutions GmbH" {
		t.Errorf("MACVendor = %q, want the mac address's vendor", result.MACVendor)
	}
}

func TestApplyMACAddressNoMAC(t *testing.T) {
	// A routed (non-local-segment) target: nmap only reports the ipv4
	// address, no mac - this is the common case for most internal
	// network scans, not an edge case.
	result := &HostResult{}
	applyMACAddress(result, []nmapAddress{{Addr: "10.0.0.5", AddrType: "ipv4"}})
	if result.MACAddress != "" || result.MACVendor != "" {
		t.Errorf("expected no changes when no mac-typed address is present, got %+v", result)
	}
}

// TestDiscoveredFromNmapRun covers RunNmapDiscovery's XML-to-map
// conversion (the IPv6 target path's stand-in for RunMasscan) against XML
// shaped like a real "nmap -6 -sS" result covering two targets - one with
// an open and a closed port, one fully closed - without needing a real
// nmap binary.
func TestDiscoveredFromNmapRun(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/></port>
    </ports>
  </host>
  <host>
    <address addr="2001:db8::2" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="filtered"/></port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	discovered := discoveredFromNmapRun(&run)

	if len(discovered) != 1 {
		t.Fatalf("expected only the host with an open port to appear, got %d host(s): %+v", len(discovered), discovered)
	}
	ports, ok := discovered["2001:db8::1"]
	if !ok {
		t.Fatalf("expected 2001:db8::1 in the discovered map, got %+v", discovered)
	}
	if len(ports) != 1 || ports[0].Port != 22 || ports[0].State != "open" {
		t.Errorf("expected only port 22/open, got %+v", ports)
	}
	if _, ok := discovered["2001:db8::2"]; ok {
		t.Errorf("host with no open ports should not appear in the discovered map")
	}
}

func TestDiscoveredFromNmapRunNoAddress(t *testing.T) {
	// Defensive: a host element with no ipv6-typed address at all (should
	// never happen against a real -6 scan, but must not panic or silently
	// attribute ports to an empty-string key).
	run := &nmapRun{Hosts: []nmapHost{{}}}
	discovered := discoveredFromNmapRun(run)
	if len(discovered) != 0 {
		t.Errorf("expected an empty map, got %+v", discovered)
	}
}
