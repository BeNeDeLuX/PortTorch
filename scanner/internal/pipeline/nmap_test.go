package pipeline

import (
	"encoding/xml"
	"strings"
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

func TestIsSMBPort(t *testing.T) {
	cases := []struct {
		name string
		port PortResult
		want bool
	}{
		{"named microsoft-ds", PortResult{Port: 4000, ServiceName: "microsoft-ds"}, true},
		{"named netbios-ssn", PortResult{Port: 4000, ServiceName: "netbios-ssn"}, true},
		{"unknown on 445", PortResult{Port: 445, ServiceName: "unknown"}, true},
		{"unknown on 139", PortResult{Port: 139, ServiceName: "unknown"}, true},
		{"unrelated service", PortResult{Port: 445 + 1, ServiceName: "http"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isSMBPort(c.port); got != c.want {
				t.Errorf("isSMBPort(%+v) = %v, want %v", c.port, got, c.want)
			}
		})
	}
}

// TestHostResultFromNmapHostFTPAndSMB covers both new NSE scripts against
// XML shaped like a real "nmap --script=ftp-anon,smb-enum-shares" result:
// ftp-anon is a per-port script attached directly to the FTP port's own
// <script> list, while smb-enum-shares is a host-level script under
// <hostscript> - this checks both parse into the right place, and that
// the host-level SMB output only gets copied onto the SMB-classified port
// (445), not the unrelated FTP port (21) that happens to be on the same
// host.
func TestHostResultFromNmapHostFTPAndSMB(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostscript>
      <script id="smb-enum-shares" output="account_used: guest&#10;print$: &#10;  Type: STYPE_DISKTREE&#10;  Anonymous access: READ&#10;backup: &#10;  Type: STYPE_DISKTREE&#10;  Anonymous access: READ/WRITE"/>
    </hostscript>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp"/>
        <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#10;-rw-r--r--    1 0  0  123 Jan 01  2020 readme.txt"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(run.Hosts))
	}

	result := hostResultFromNmapHost("10.0.0.5", run.Hosts[0])
	if len(result.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d: %+v", len(result.Ports), result.Ports)
	}

	ftpPort := result.Ports[0]
	if ftpPort.Port != 21 {
		t.Fatalf("expected first port to be 21, got %d", ftpPort.Port)
	}
	if ftpPort.FTPAnonListing == "" || !strings.Contains(ftpPort.FTPAnonListing, "readme.txt") {
		t.Errorf("expected ftp-anon output with the directory listing, got %q", ftpPort.FTPAnonListing)
	}
	if ftpPort.SMBShares != "" {
		t.Errorf("the FTP port must not get the SMB host-script output, got %q", ftpPort.SMBShares)
	}

	smbPort := result.Ports[1]
	if smbPort.Port != 445 {
		t.Fatalf("expected second port to be 445, got %d", smbPort.Port)
	}
	if smbPort.SMBShares == "" || !strings.Contains(smbPort.SMBShares, "backup") {
		t.Errorf("expected smb-enum-shares output with the share list, got %q", smbPort.SMBShares)
	}
	if smbPort.FTPAnonListing != "" {
		t.Errorf("the SMB port must not get the FTP port's own script output, got %q", smbPort.FTPAnonListing)
	}
}

// TestHostResultFromNmapHostExtraScripts covers the generic "everything
// else goes into ExtraScripts" path (nfs-showmount/rsync-list-modules/
// ldap-rootdse/the open-database checks, and implicitly any future script
// added to RunNmap's --script list) - checks that scripts with dedicated
// fields (banner, ftp-anon) are NOT duplicated into ExtraScripts, that
// scripts nmap ran but found nothing for (empty output, e.g. redis-info
// against a server that required AUTH) are dropped rather than stored as
// a blank entry, and that a real result (mongodb-databases) is captured
// with both id and output intact.
func TestHostResultFromNmapHostExtraScripts(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="27017">
        <state state="open"/>
        <service name="mongod"/>
        <script id="banner" output="It looks like you are trying to access MongoDB over HTTP"/>
        <script id="mongodb-databases" output="ok: 1.0&#10;databases&#10;  admin&#10;  config&#10;  customer_exports"/>
        <script id="redis-info" output=""/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	result := hostResultFromNmapHost("10.0.0.9", run.Hosts[0])
	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(result.Ports))
	}
	port := result.Ports[0]

	if port.Banner != "It looks like you are trying to access MongoDB over HTTP" {
		t.Errorf("banner should still go to its own dedicated field, got %q", port.Banner)
	}

	if len(port.ExtraScripts) != 1 {
		t.Fatalf("expected exactly 1 extra script (banner excluded, empty redis-info dropped), got %d: %+v", len(port.ExtraScripts), port.ExtraScripts)
	}
	extra := port.ExtraScripts[0]
	if extra.ID != "mongodb-databases" || !strings.Contains(extra.Output, "customer_exports") {
		t.Errorf("expected mongodb-databases with its output, got %+v", extra)
	}
	for _, s := range port.ExtraScripts {
		if s.ID == "banner" {
			t.Errorf("banner must not be duplicated into ExtraScripts")
		}
	}
}

// TestHostResultFromNmapHostSMBHostScriptsIntoExtraScripts covers
// smb-os-discovery and nbstat - two more host-level scripts riding the
// same SMB session as smb-enum-shares, but (unlike smb-enum-shares)
// captured generically into ExtraScripts rather than a dedicated field.
// Checks both land on the SMB port (445) alongside smb-enum-shares'
// own dedicated SMBShares field, and neither leaks onto an unrelated
// port (80) on the same host.
func TestHostResultFromNmapHostSMBHostScriptsIntoExtraScripts(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.6" addrtype="ipv4"/>
    <hostscript>
      <script id="smb-enum-shares" output="account_used: guest"/>
      <script id="smb-os-discovery" output="OS: Windows Server 2019 Standard 17763&#10;Computer name: FILESRV01&#10;Domain name: corp.example.com&#10;Workgroup: WORKGROUP"/>
      <script id="nbstat" output="NetBIOS name: FILESRV01, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: 00:11:22:33:44:55"/>
    </hostscript>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	result := hostResultFromNmapHost("10.0.0.6", run.Hosts[0])
	if len(result.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d: %+v", len(result.Ports), result.Ports)
	}

	httpPort := result.Ports[0]
	if httpPort.Port != 80 {
		t.Fatalf("expected first port to be 80, got %d", httpPort.Port)
	}
	if len(httpPort.ExtraScripts) != 0 {
		t.Errorf("the unrelated HTTP port must not get any SMB host-script output, got %+v", httpPort.ExtraScripts)
	}

	smbPort := result.Ports[1]
	if smbPort.Port != 445 {
		t.Fatalf("expected second port to be 445, got %d", smbPort.Port)
	}
	if smbPort.SMBShares == "" {
		t.Errorf("smb-enum-shares should still populate its own dedicated field")
	}
	if len(smbPort.ExtraScripts) != 2 {
		t.Fatalf("expected exactly 2 extra scripts (smb-os-discovery, nbstat), got %d: %+v", len(smbPort.ExtraScripts), smbPort.ExtraScripts)
	}
	byID := map[string]string{}
	for _, s := range smbPort.ExtraScripts {
		byID[s.ID] = s.Output
	}
	if !strings.Contains(byID["smb-os-discovery"], "FILESRV01") {
		t.Errorf("expected smb-os-discovery output with the computer name, got %+v", smbPort.ExtraScripts)
	}
	if !strings.Contains(byID["nbstat"], "NetBIOS name") {
		t.Errorf("expected nbstat output, got %+v", smbPort.ExtraScripts)
	}
	if _, ok := byID["smb-enum-shares"]; ok {
		t.Errorf("smb-enum-shares must not be duplicated into ExtraScripts - it has its own dedicated SMBShares field")
	}
}

// TestHostResultFromNmapHostHTTPMethods checks "http-methods" - a
// per-port script - flows through the same generic default case as the
// other ExtraScripts entries, with no special-casing needed.
func TestHostResultFromNmapHostHTTPMethods(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="http-methods" output="Supported Methods: GET HEAD POST OPTIONS PUT DELETE&#10;Potentially risky methods: PUT DELETE"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	result := hostResultFromNmapHost("10.0.0.7", run.Hosts[0])
	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(result.Ports))
	}
	if len(result.Ports[0].ExtraScripts) != 1 || result.Ports[0].ExtraScripts[0].ID != "http-methods" {
		t.Fatalf("expected exactly 1 extra script (http-methods), got %+v", result.Ports[0].ExtraScripts)
	}
	if !strings.Contains(result.Ports[0].ExtraScripts[0].Output, "PUT DELETE") {
		t.Errorf("expected http-methods output with the risky-methods line, got %q", result.Ports[0].ExtraScripts[0].Output)
	}
}

// TestHostResultFromNmapHostTier1Scripts covers a representative sample
// of the "Tier 1" NSE script round (http-auth, http-git, rdp-ntlm-info,
// ssh2-enum-algos) against realistic per-port output, confirming each
// lands as its own ExtraScripts entry on the correct port and nothing
// leaks across ports on the same host.
func TestHostResultFromNmapHostTier1Scripts(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
        <script id="ssh2-enum-algos" output="kex_algorithms: (4)&#10;    curve25519-sha256&#10;    ecdh-sha2-nistp256"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="http-auth" output="HTTP/1.1 401 Unauthorized&#10;  Basic realm=Internal Admin"/>
        <script id="http-git" output="/.git/HEAD Git repository found!"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server"/>
        <script id="rdp-ntlm-info" output="Target_Name: CORP&#10;NetBIOS_Domain_Name: CORP&#10;NetBIOS_Computer_Name: JUMPHOST01&#10;Product_Version: 10.0.17763"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	result := hostResultFromNmapHost("10.0.0.8", run.Hosts[0])
	if len(result.Ports) != 3 {
		t.Fatalf("expected 3 ports, got %d: %+v", len(result.Ports), result.Ports)
	}

	sshPort := result.Ports[0]
	if len(sshPort.ExtraScripts) != 1 || sshPort.ExtraScripts[0].ID != "ssh2-enum-algos" {
		t.Fatalf("expected exactly 1 extra script (ssh2-enum-algos) on port 22, got %+v", sshPort.ExtraScripts)
	}

	httpPort := result.Ports[1]
	if len(httpPort.ExtraScripts) != 2 {
		t.Fatalf("expected exactly 2 extra scripts (http-auth, http-git) on port 80, got %+v", httpPort.ExtraScripts)
	}
	httpByID := map[string]string{}
	for _, s := range httpPort.ExtraScripts {
		httpByID[s.ID] = s.Output
	}
	if !strings.Contains(httpByID["http-auth"], "Basic realm") {
		t.Errorf("expected http-auth output with the realm, got %+v", httpPort.ExtraScripts)
	}
	if !strings.Contains(httpByID["http-git"], "Git repository found") {
		t.Errorf("expected http-git output, got %+v", httpPort.ExtraScripts)
	}

	rdpPort := result.Ports[2]
	if len(rdpPort.ExtraScripts) != 1 || rdpPort.ExtraScripts[0].ID != "rdp-ntlm-info" {
		t.Fatalf("expected exactly 1 extra script (rdp-ntlm-info) on port 3389, got %+v", rdpPort.ExtraScripts)
	}
	if !strings.Contains(rdpPort.ExtraScripts[0].Output, "JUMPHOST01") {
		t.Errorf("expected rdp-ntlm-info output with the computer name, got %q", rdpPort.ExtraScripts[0].Output)
	}

	// Nothing must leak across ports.
	for _, s := range sshPort.ExtraScripts {
		if s.ID == "http-auth" || s.ID == "rdp-ntlm-info" {
			t.Errorf("unrelated script %q leaked onto the SSH port", s.ID)
		}
	}
}

// TestHostResultFromNmapHostTier2Scripts covers the "Tier 2" round
// (rpcinfo, msrpc-enum, memcached-info, oracle-tns-version) against
// realistic per-port output, same generic-capture confirmation as
// TestHostResultFromNmapHostTier1Scripts above.
func TestHostResultFromNmapHostTier2Scripts(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="111">
        <state state="open"/>
        <service name="rpcbind"/>
        <script id="rpcinfo" output="100000  2,3,4        111/tcp  rpcbind&#10;100003  2,3           2049/tcp  nfs"/>
      </port>
      <port protocol="tcp" portid="135">
        <state state="open"/>
        <service name="msrpc"/>
        <script id="msrpc-enum" output="uuid: 12345778-1234-abcd-ef00-0123456789ac&#10;  tcp_port: 49664&#10;  version: 1"/>
      </port>
      <port protocol="tcp" portid="11211">
        <state state="open"/>
        <service name="memcache"/>
        <script id="memcached-info" output="Process ID: 1234&#10;Uptime: 86400 seconds&#10;Pointer Size: 64 bits"/>
      </port>
      <port protocol="tcp" portid="1521">
        <state state="open"/>
        <service name="oracle-tns"/>
        <script id="oracle-tns-version" output="TNS Version: 3.19.0&#10;Unauthorized: false"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	result := hostResultFromNmapHost("10.0.0.10", run.Hosts[0])
	if len(result.Ports) != 4 {
		t.Fatalf("expected 4 ports, got %d: %+v", len(result.Ports), result.Ports)
	}

	wantByPort := map[int]struct {
		id  string
		sub string
	}{
		111:   {"rpcinfo", "rpcbind"},
		135:   {"msrpc-enum", "49664"},
		11211: {"memcached-info", "Uptime"},
		1521:  {"oracle-tns-version", "TNS Version"},
	}
	for _, p := range result.Ports {
		want, ok := wantByPort[p.Port]
		if !ok {
			t.Fatalf("unexpected port %d in result", p.Port)
		}
		if len(p.ExtraScripts) != 1 || p.ExtraScripts[0].ID != want.id {
			t.Fatalf("port %d: expected exactly 1 extra script (%s), got %+v", p.Port, want.id, p.ExtraScripts)
		}
		if !strings.Contains(p.ExtraScripts[0].Output, want.sub) {
			t.Errorf("port %d: expected output containing %q, got %q", p.Port, want.sub, p.ExtraScripts[0].Output)
		}
	}
}

// UDP support hinges on two things staying true: a TCP-only scan must
// produce exactly the argument it always did, and a mixed scan must reach
// nmap in nmap's own T:/U: grammar with the right scan-type flags.
func TestNmapPortSpecTCPOnlyIsUnchanged(t *testing.T) {
	ports := []PortResult{
		{Port: 22, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
	}
	spec, needsUDP, needsTCP := nmapPortSpec(ports)
	if spec != "22,443" {
		t.Fatalf("TCP-only spec = %q, want the same bare list as before UDP existed", spec)
	}
	if needsUDP {
		t.Fatal("needsUDP = true for a TCP-only set")
	}
	if !needsTCP {
		t.Fatal("needsTCP = false for a TCP-only set")
	}
}

func TestNmapPortSpecMixedProtocols(t *testing.T) {
	ports := []PortResult{
		{Port: 80, Protocol: "tcp"},
		{Port: 53, Protocol: "udp"},
		{Port: 161, Protocol: "UDP"}, // case shouldn't matter
	}
	spec, needsUDP, needsTCP := nmapPortSpec(ports)
	if spec != "T:80,U:53,161" {
		t.Fatalf("mixed spec = %q, want T:80,U:53,161", spec)
	}
	if !needsUDP || !needsTCP {
		t.Fatalf("needsUDP=%v needsTCP=%v, want both true", needsUDP, needsTCP)
	}
}

func TestNmapPortSpecUDPOnly(t *testing.T) {
	spec, needsUDP, needsTCP := nmapPortSpec([]PortResult{{Port: 53, Protocol: "udp"}})
	if spec != "U:53" {
		t.Fatalf("UDP-only spec = %q, want U:53", spec)
	}
	if !needsUDP {
		t.Fatal("needsUDP = false for a UDP-only set")
	}
	if needsTCP {
		t.Fatal("needsTCP = true for a UDP-only set")
	}
}

func TestNmapPortSpecTreatsEmptyProtocolAsTCP(t *testing.T) {
	// PortResults built by parts of the pipeline other than masscan don't
	// always set Protocol; defaulting to UDP there would silently turn a
	// TCP enrichment into a UDP one.
	spec, needsUDP, _ := nmapPortSpec([]PortResult{{Port: 8080}})
	if spec != "8080" || needsUDP {
		t.Fatalf("spec = %q needsUDP = %v, want 8080/false", spec, needsUDP)
	}
}
