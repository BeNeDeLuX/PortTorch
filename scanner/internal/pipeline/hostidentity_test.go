package pipeline

import "testing"

// The exact strings a live host produced, kept verbatim rather than
// tidied: the trailing "\x00" on the NetBIOS name and the "<unknown>"
// MAC are both real, and both are what the parser has to survive.
const realSMBOSDiscovery = `
  OS: Windows 6.1 (Samba 4.22.10)
  Computer name: filer02
  NetBIOS computer name: FILER02\x00
  Domain name: 
  FQDN: filer02
  System time: 2026-09-25T11:13:17+02:00
`

const realNbstat = `NetBIOS name: FILER02, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
Names:
  FILER02<00>          Flags: <unique><active>
  FILER02<03>          Flags: <unique><active>
  MY-NETWORK<00>       Flags: <group><active>`

// A domain-joined Windows host, where the FQDN field earns its name.
const domainJoinedSMBOSDiscovery = `
  OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
  Computer name: WS-APP-01
  NetBIOS computer name: WS-APP-01\x00
  Domain name: corp.example.internal
  FQDN: ws-app-01.corp.example.internal
  System time: 2026-09-25T11:13:17+02:00
`

const windowsNbstat = `NetBIOS name: WS-APP-01, NetBIOS user: <unknown>, NetBIOS MAC: 00:15:5d:01:2a:0b (Microsoft)
Names:
  WS-APP-01<00>        Flags: <unique><active>`

func smbHost(scripts ...NSEScript) *HostResult {
	return &HostResult{
		IP:    "10.0.0.5",
		Ports: []PortResult{{Port: 445, Protocol: "tcp", State: "open", ServiceName: "microsoft-ds", ExtraScripts: scripts}},
	}
}

func TestDeriveHostnamePrefersFQDNOverShortName(t *testing.T) {
	host := smbHost(NSEScript{ID: "smb-os-discovery", Output: domainJoinedSMBOSDiscovery})
	deriveHostIdentity(host)
	if host.DerivedHostname != "ws-app-01.corp.example.internal" {
		t.Errorf("DerivedHostname = %q, want the FQDN", host.DerivedHostname)
	}
	if host.DerivedHostnameSource != IdentitySourceSMBOSDiscovery {
		t.Errorf("source = %q, want %q", host.DerivedHostnameSource, IdentitySourceSMBOSDiscovery)
	}
}

// nmap builds the FQDN field from computer name plus domain, so on a
// machine that is not domain-joined it holds the short name - which is
// why a dot, not the field name, decides whether it is worth preferring.
func TestDeriveHostnameFallsBackToComputerNameWhenFQDNHasNoDomain(t *testing.T) {
	host := smbHost(NSEScript{ID: "smb-os-discovery", Output: realSMBOSDiscovery})
	deriveHostIdentity(host)
	if host.DerivedHostname != "filer02" {
		t.Errorf("DerivedHostname = %q, want %q", host.DerivedHostname, "filer02")
	}
}

func TestDeriveHostnameFromNbstatStripsTheNetBIOSPadding(t *testing.T) {
	host := smbHost(NSEScript{ID: "nbstat", Output: realNbstat})
	deriveHostIdentity(host)
	if host.DerivedHostname != "FILER02" {
		t.Errorf("DerivedHostname = %q, want %q", host.DerivedHostname, "FILER02")
	}
	if host.DerivedHostnameSource != IdentitySourceNbstat {
		t.Errorf("source = %q, want nbstat", host.DerivedHostnameSource)
	}
}

// The RDP certificate outranks both, because Windows puts the machine's
// own name in its subject and often the full FQDN.
func TestRDPCertificateOutranksSMB(t *testing.T) {
	host := smbHost(NSEScript{ID: "smb-os-discovery", Output: domainJoinedSMBOSDiscovery})
	host.Ports = append(host.Ports, PortResult{Port: 3389, Protocol: "tcp", State: "open", ServiceName: "ms-wbt-server"})
	host.TLSCertificates = []TLSCertificate{{Port: 3389, SubjectCN: "ws-rdp-01.corp.example.internal"}}
	deriveHostIdentity(host)
	if host.DerivedHostname != "ws-rdp-01.corp.example.internal" {
		t.Errorf("DerivedHostname = %q, want the RDP certificate's CN", host.DerivedHostname)
	}
	if host.DerivedHostnameSource != IdentitySourceRDPCertificate {
		t.Errorf("source = %q, want the RDP certificate", host.DerivedHostnameSource)
	}
}

// A certificate from a non-RDP port says nothing about the machine's
// name - a wildcard or a service label is normal there, and writing one
// into a hostname field would be worse than leaving it empty.
func TestCertificateOnANonRDPPortIsIgnored(t *testing.T) {
	host := &HostResult{
		IP:              "10.0.0.5",
		Ports:           []PortResult{{Port: 443, Protocol: "tcp", State: "open", ServiceName: "https"}},
		TLSCertificates: []TLSCertificate{{Port: 443, SubjectCN: "*.example.internal"}},
	}
	deriveHostIdentity(host)
	if host.DerivedHostname != "" {
		t.Errorf("DerivedHostname = %q, want nothing from a web certificate", host.DerivedHostname)
	}
}

// An RDP certificate on a host with no name to present carries the
// address instead, which is the one case there is nothing to gain from.
func TestAnIPInACertificateIsNotAHostname(t *testing.T) {
	host := &HostResult{
		IP:              "10.0.0.5",
		Ports:           []PortResult{{Port: 3389, Protocol: "tcp", State: "open", ServiceName: "ms-wbt-server"}},
		TLSCertificates: []TLSCertificate{{Port: 3389, SubjectCN: "10.0.0.5"}},
	}
	deriveHostIdentity(host)
	if host.DerivedHostname != "" {
		t.Errorf("DerivedHostname = %q, want an address not to be taken for a name", host.DerivedHostname)
	}
}

// The whole point: a real PTR record is never displaced.
func TestNothingIsDerivedWhenTheRealValuesExist(t *testing.T) {
	host := smbHost(NSEScript{ID: "nbstat", Output: windowsNbstat})
	host.Hostname = "filer01.corp.example.internal"
	host.MACAddress = "AA:BB:CC:DD:EE:FF"
	deriveHostIdentity(host)
	if host.DerivedHostname != "" || host.DerivedMACAddress != "" {
		t.Errorf("derived %q/%q over existing values", host.DerivedHostname, host.DerivedMACAddress)
	}
	if host.Hostname != "filer01.corp.example.internal" || host.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Error("the real values were modified")
	}
}

func TestDeriveMACFromNbstatWithVendor(t *testing.T) {
	host := smbHost(NSEScript{ID: "nbstat", Output: windowsNbstat})
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "00:15:5D:01:2A:0B" {
		t.Errorf("DerivedMACAddress = %q, want the uppercased address", host.DerivedMACAddress)
	}
	if host.DerivedMACVendor != "Microsoft" {
		t.Errorf("DerivedMACVendor = %q, want Microsoft", host.DerivedMACVendor)
	}
	if host.DerivedMACSource != IdentitySourceNbstat {
		t.Errorf("source = %q, want nbstat", host.DerivedMACSource)
	}
}

// Samba answers nbstat without a MAC, which is what the live sample
// shows. "<unknown> (unknown)" must not become an address or a vendor.
func TestNbstatWithoutAMACYieldsNothing(t *testing.T) {
	host := smbHost(NSEScript{ID: "nbstat", Output: realNbstat})
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "" || host.DerivedMACVendor != "" {
		t.Errorf("derived %q/%q from an unknown MAC", host.DerivedMACAddress, host.DerivedMACVendor)
	}
	// The name in the same line is still perfectly good.
	if host.DerivedHostname != "FILER02" {
		t.Errorf("DerivedHostname = %q, want the name to survive the missing MAC", host.DerivedHostname)
	}
}

func TestAllZeroMACIsRejected(t *testing.T) {
	host := smbHost(NSEScript{ID: "nbstat", Output: "NetBIOS name: WS-01, NetBIOS MAC: 00:00:00:00:00:00 (unknown)"})
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "" {
		t.Errorf("DerivedMACAddress = %q, want an all-zero address rejected", host.DerivedMACAddress)
	}
}

func TestPlausibleHostname(t *testing.T) {
	good := []string{"ws-app-01", "WS-APP-01", "ws-app-01.corp.example.internal", "a", "host1.sub.domain.tld"}
	bad := []string{"", "   ", "10.0.0.5", "fe80::1", "*.example.internal", "-leading", "trailing-", "two..dots", "has space", "SMB Server"}
	for _, v := range good {
		if !plausibleHostname(v) {
			t.Errorf("plausibleHostname(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if plausibleHostname(v) {
			t.Errorf("plausibleHostname(%q) = true, want false", v)
		}
	}
}

// The scripts are host-level, so their output is copied onto every SMB
// port - an empty copy on one port must not mask a populated one.
func TestAnEmptyCopyDoesNotMaskAPopulatedOne(t *testing.T) {
	host := &HostResult{
		IP: "10.0.0.5",
		Ports: []PortResult{
			{Port: 139, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: "nbstat", Output: "   "}}},
			{Port: 445, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: "nbstat", Output: windowsNbstat}}},
		},
	}
	deriveHostIdentity(host)
	if host.DerivedHostname != "WS-APP-01" {
		t.Errorf("DerivedHostname = %q, want the populated copy to win", host.DerivedHostname)
	}
}

// The snmp-interfaces output a real CS141 UPS management card returned,
// in the shape nmap's own script builds it (an interface name, then its
// indented fields). Three interfaces, only one of them carrying the
// scanned address.
const realSNMPInterfaces = `
  lo
    IP address: 127.0.0.1  Netmask: 255.0.0.0
    Type: softwareLoopback  Speed: 10 Mbps
    Status: up
    Traffic stats: 3.28 Gb sent, 3.28 Gb received
  eth0
    IP address: 10.41.72.135  Netmask: 255.255.248.0
    MAC address: 00:30:d6:39:36:16 (MSC Vertriebs Gmbh)
    Type: ethernetCsmacd  Speed: 1 Gbps
    Status: up
    Traffic stats: 1.20 Gb sent, 2.19 Gb received
  sit0
    Type: tunnel  Speed: 0 Kbps
    Status: down
    Traffic stats: 0.00 Kb sent, 0.00 Kb received
`

// The SNMP probe appends its result as a synthetic UDP/161 port - see
// snmp.go - which is where deriveHostIdentity finds it.
func snmpHost(ip, interfaces string) *HostResult {
	return &HostResult{
		IP: ip,
		Ports: []PortResult{
			{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"},
			{Port: 161, Protocol: "udp", State: "open", ServiceName: "snmp", ExtraScripts: []NSEScript{{ID: "snmp-interfaces", Output: interfaces}}},
		},
	}
}

func TestDeriveMACFromTheSNMPInterfaceCarryingTheScannedAddress(t *testing.T) {
	host := snmpHost("10.41.72.135", realSNMPInterfaces)
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "00:30:D6:39:36:16" {
		t.Errorf("DerivedMACAddress = %q, want eth0's address", host.DerivedMACAddress)
	}
	if host.DerivedMACVendor != "MSC Vertriebs Gmbh" {
		t.Errorf("DerivedMACVendor = %q", host.DerivedMACVendor)
	}
	if host.DerivedMACSource != IdentitySourceSNMPInterfaces {
		t.Errorf("source = %q, want snmp-interfaces", host.DerivedMACSource)
	}
}

// A router reports every interface it has. Taking the first MAC in the
// table would record a real address that belongs to another network -
// so an address the device does not list (NAT, a VIP) yields nothing.
func TestSNMPInterfaceMACNeedsTheScannedAddress(t *testing.T) {
	host := snmpHost("192.0.2.50", realSNMPInterfaces)
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "" {
		t.Errorf("took %q from an interface that is not the scanned address", host.DerivedMACAddress)
	}

	router := `
  ge-0/0/0
    IP address: 10.1.0.1  Netmask: 255.255.255.0
    MAC address: 00:11:22:33:44:01 (Juniper Networks)
  ge-0/0/1
    IP address: 10.2.0.1  Netmask: 255.255.255.0
    MAC address: 00:11:22:33:44:02 (Juniper Networks)
`
	host = snmpHost("10.2.0.1", router)
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "00:11:22:33:44:02" {
		t.Errorf("DerivedMACAddress = %q, want the second interface's", host.DerivedMACAddress)
	}
}

// The scanned interface tells us its address but carries no MAC (a
// tunnel, or a point-to-point link) - another interface's MAC must not
// be borrowed for it.
func TestSNMPMatchedInterfaceWithoutAMACYieldsNothing(t *testing.T) {
	output := `
  ppp0
    IP address: 10.9.9.9  Netmask: 255.255.255.255
    Type: ppp  Speed: 0 Kbps
  eth0
    IP address: 10.0.0.1  Netmask: 255.255.255.0
    MAC address: 00:aa:bb:cc:dd:ee (unknown)
`
	host := snmpHost("10.9.9.9", output)
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "" {
		t.Errorf("borrowed %q from a different interface", host.DerivedMACAddress)
	}
}

// SNMP outranks nbstat: it names the MAC of the scanned address itself,
// where NetBIOS answers from whichever adapter it likes.
func TestSNMPInterfaceMACOutranksNbstat(t *testing.T) {
	host := snmpHost("10.41.72.135", realSNMPInterfaces)
	host.Ports = append(host.Ports, PortResult{Port: 445, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: "nbstat", Output: windowsNbstat}}})
	deriveHostIdentity(host)
	if host.DerivedMACSource != IdentitySourceSNMPInterfaces {
		t.Errorf("source = %q, want snmp-interfaces to win", host.DerivedMACSource)
	}
}

// An ARP-resolved MAC is direct evidence and is never second-guessed.
func TestSNMPDoesNotOverrideARP(t *testing.T) {
	host := snmpHost("10.41.72.135", realSNMPInterfaces)
	host.MACAddress = "00:30:D6:39:36:16"
	deriveHostIdentity(host)
	if host.DerivedMACAddress != "" {
		t.Error("derived a MAC although ARP already resolved one")
	}
}
