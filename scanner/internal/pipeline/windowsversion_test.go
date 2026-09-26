package pipeline

import "testing"

// nmap's own documented output for rdp-ntlm-info, copied from the
// script's @output block rather than paraphrased - the field names and
// the two-space indent are what the parser actually has to survive.
const realRDPNtlmInfo = `
  Target_Name: W2016
  NetBIOS_Domain_Name: W2016
  NetBIOS_Computer_Name: W16GA-SRV01
  DNS_Domain_Name: W2016.lab
  DNS_Computer_Name: W16GA-SRV01.W2016.lab
  DNS_Tree_Name: W2016.lab
  Product_Version: 10.0.14393
  System_Time: 2019-06-13T10:38:35+00:00
`

func ntlmHost(script string, output string) *HostResult {
	return &HostResult{
		IP:    "10.0.0.5",
		Ports: []PortResult{{Port: 3389, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: script, Output: output}}}},
	}
}

// The whole point: nmap's -O says "Windows 10|11|Server 2016-2022", NTLM
// says exactly which build.
func TestWindowsBuildFromRDPNtlmInfo(t *testing.T) {
	host := ntlmHost("rdp-ntlm-info", realRDPNtlmInfo)
	deriveHostIdentity(host)
	if host.WindowsBuild != "10.0.14393" {
		t.Errorf("WindowsBuild = %q, want 10.0.14393", host.WindowsBuild)
	}
	if host.WindowsBuildSource != "rdp-ntlm-info" {
		t.Errorf("source = %q", host.WindowsBuildSource)
	}
}

// A Windows host with no RDP exposed still answers over IIS, Exchange or
// MSSQL - which is why the other seven scripts were added.
func TestWindowsBuildFromAnyNtlmService(t *testing.T) {
	for _, script := range []string{"http-ntlm-info", "smtp-ntlm-info", "ms-sql-ntlm-info", "telnet-ntlm-info"} {
		host := ntlmHost(script, "  Target_Name: CORP\n  Product_Version: 10.0.20348\n")
		deriveHostIdentity(host)
		if host.WindowsBuild != "10.0.20348" {
			t.Errorf("%s: WindowsBuild = %q", script, host.WindowsBuild)
		}
		if host.WindowsBuildSource != script {
			t.Errorf("%s: source = %q", script, host.WindowsBuildSource)
		}
	}
}

// Not every NTLM answer carries a version - a non-Windows implementation
// may answer without one, and inventing a build there would be worse
// than reporting none.
func TestNoWindowsBuildWhenNTLMCarriesNone(t *testing.T) {
	host := ntlmHost("http-ntlm-info", "  Target_Name: SOMETHING\n  NetBIOS_Computer_Name: BOX\n")
	deriveHostIdentity(host)
	if host.WindowsBuild != "" {
		t.Errorf("WindowsBuild = %q, want nothing", host.WindowsBuild)
	}
}

func TestWindowsBuildRejectsMalformedVersions(t *testing.T) {
	for _, bad := range []string{"10.0", "not.a.version", "10.0.17763.1234 (something)", ""} {
		host := ntlmHost("rdp-ntlm-info", "  Product_Version: "+bad+"\n")
		deriveHostIdentity(host)
		if host.WindowsBuild != "" {
			t.Errorf("accepted %q as a build", bad)
		}
	}
}

// The NTLM message's DNS_Computer_Name is the full FQDN, and a
// domain-joined machine answers it even with SMB1 off - which is exactly
// when smb-os-discovery gives nothing. So it outranks SMB in the chain.
func TestNTLMFQDNOutranksSMBForTheHostname(t *testing.T) {
	host := ntlmHost("rdp-ntlm-info", realRDPNtlmInfo)
	host.Ports = append(host.Ports, PortResult{
		Port: 445, Protocol: "tcp", State: "open",
		ExtraScripts: []NSEScript{{ID: "smb-os-discovery", Output: "  Computer name: w16ga-srv01\n  FQDN: w16ga-srv01\n"}},
	})
	deriveHostIdentity(host)
	if host.DerivedHostname != "W16GA-SRV01.W2016.lab" {
		t.Errorf("DerivedHostname = %q, want the NTLM FQDN", host.DerivedHostname)
	}
	if host.DerivedHostnameSource != "rdp-ntlm-info" {
		t.Errorf("source = %q", host.DerivedHostnameSource)
	}
}

// ...but a real PTR record still wins over all of it, unchanged.
func TestNTLMDoesNotDisplaceARealHostname(t *testing.T) {
	host := ntlmHost("rdp-ntlm-info", realRDPNtlmInfo)
	host.Hostname = "srv01.corp.example.internal"
	deriveHostIdentity(host)
	if host.DerivedHostname != "" {
		t.Errorf("derived %q over a real PTR record", host.DerivedHostname)
	}
	// The build is still worth having - it is not competing with anything.
	if host.WindowsBuild != "10.0.14393" {
		t.Errorf("WindowsBuild = %q, want it regardless of the hostname", host.WindowsBuild)
	}
}

// Ordering is by script, not by whichever port happened to be parsed
// first, so a host answering on several services reports a stable source.
func TestWindowsBuildSourceIsStableAcrossPorts(t *testing.T) {
	host := &HostResult{
		IP: "10.0.0.5",
		Ports: []PortResult{
			{Port: 25, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: "smtp-ntlm-info", Output: "  Product_Version: 10.0.17763\n"}}},
			{Port: 3389, Protocol: "tcp", State: "open", ExtraScripts: []NSEScript{{ID: "rdp-ntlm-info", Output: "  Product_Version: 10.0.17763\n"}}},
		},
	}
	deriveHostIdentity(host)
	if host.WindowsBuildSource != "rdp-ntlm-info" {
		t.Errorf("source = %q, want the first script in the documented order", host.WindowsBuildSource)
	}
}
