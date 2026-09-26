package pipeline

import (
	"net"
	"regexp"
	"strings"
)

// Filling in a host's name and MAC from what the scan already saw, for
// the cases reverse DNS and ARP cannot cover.
//
// Two gaps this closes, both common on an internal network:
//
//   - A Windows host with no PTR record has no name at all in the
//     dashboard, even though it announces one over RDP and SMB.
//   - MAC addresses are only ever resolved by ARP, so a host one routed
//     hop away never has one - but a Windows host will hand its own out
//     over NetBIOS, which travels across routers.
//
// Everything here is derived from output the pipeline already collects
// (the RDP certificate probe, and the smb-os-discovery/nbstat scripts
// that run on every SMB port) - no extra probe, no extra scan time.
//
// **Nothing is ever overwritten.** These land in their own fields and are
// only derived at all when the real value is missing: a PTR record and an
// ARP-resolved MAC are direct evidence, while a machine's own claim about
// its name is exactly that, a claim. Keeping them apart is also what lets
// the two disagree visibly - measured on a real fleet, a host whose PTR
// said "filer01.example.internal" reported itself over SMB as "FILER02",
// and which of those is wrong is not something a scanner can decide.
//
// The source is recorded with the value for the same reason: "this name
// came from an RDP certificate" and "this name is in DNS" are different
// kinds of fact, and a consumer that cannot tell them apart will treat
// the weaker one as the stronger.

const (
	IdentitySourceRDPCertificate = "rdp-certificate"
	IdentitySourceSMBOSDiscovery = "smb-os-discovery"
	IdentitySourceNbstat         = "nbstat"
)

// Deliberately strict: this only has to accept the shapes a Windows host
// actually reports, and anything it wrongly accepts becomes a hostname in
// the dashboard. No leading/trailing dot or hyphen, no empty labels, and
// nothing that parses as an IP address - an RDP certificate's CN is the
// machine's address itself on a host that has no name to present, which
// is precisely the case there is nothing to gain from.
var hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

func plausibleHostname(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// nmap prints a MAC as six colon-separated hex pairs, and nbstat appends
// its own vendor lookup in brackets after it.
var macPattern = regexp.MustCompile(`\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b`)

func plausibleMAC(value string) bool {
	if !macPattern.MatchString(value) {
		return false
	}
	// nbstat prints an all-zero MAC when it has nothing, which is not an
	// address anyone wants recorded as one.
	return strings.ToLower(value) != "00:00:00:00:00:00"
}

// deriveHostIdentity fills DerivedHostname/DerivedMACAddress from the
// host's own scan evidence, in the documented order of preference, and
// only where the real field is empty.
func deriveHostIdentity(host *HostResult) {
	if host == nil {
		return
	}
	if strings.TrimSpace(host.Hostname) == "" {
		if name, source := deriveHostname(host); name != "" {
			host.DerivedHostname = name
			host.DerivedHostnameSource = source
		}
	}
	if strings.TrimSpace(host.MACAddress) == "" {
		if mac, vendor, source := deriveMAC(host); mac != "" {
			host.DerivedMACAddress = mac
			host.DerivedMACVendor = vendor
			host.DerivedMACSource = source
		}
	}
	// Unconditional, unlike the two above: there is no "real" Windows
	// build field for this to defer to. nmap's -O fingerprint reports a
	// family spanning several releases, which is a different and much
	// vaguer statement - see windowsversion.go.
	if build, source := deriveWindowsBuild(host); build != "" {
		host.WindowsBuild = build
		host.WindowsBuildSource = source
	}
}

// Order of preference, most to least trustworthy about the *DNS* name:
//
//  1. The RDP certificate. Windows generates it with the machine's own
//     name in the subject CN, frequently the full FQDN.
//  2. The NTLM message an *-ntlm-info script elicited, whose
//     DNS_Computer_Name is the full FQDN - and which a domain-joined
//     machine answers even with SMB1 disabled, where smb-os-discovery
//     below returns nothing at all.
//  3. smb-os-discovery, which reports an FQDN field - though it falls
//     back to the short name when the machine is not domain-joined, so a
//     dot is what distinguishes the two.
//  4. nbstat's NetBIOS name, which is always the short name and always
//     uppercase. Last because it is the least specific.
func deriveHostname(host *HostResult) (string, string) {
	if name := hostnameFromRDPCertificate(host); name != "" {
		return name, IdentitySourceRDPCertificate
	}
	if name, source := hostnameFromNTLM(host); name != "" {
		return name, source
	}
	for _, script := range hostScripts(host, "smb-os-discovery") {
		if name := hostnameFromSMBOSDiscovery(script); name != "" {
			return name, IdentitySourceSMBOSDiscovery
		}
	}
	for _, script := range hostScripts(host, "nbstat") {
		if name, _, _ := parseNbstat(script); name != "" {
			return name, IdentitySourceNbstat
		}
	}
	return "", ""
}

// Only nbstat actually carries a MAC - smb-os-discovery reports OS,
// computer name, domain and system time and no address at all, confirmed
// against real output. It is still consulted first so that adding a
// source later is a change in one place rather than a change of shape.
func deriveMAC(host *HostResult) (mac string, vendor string, source string) {
	for _, script := range hostScripts(host, "smb-os-discovery") {
		if m, v := macFromScriptOutput(script); m != "" {
			return m, v, IdentitySourceSMBOSDiscovery
		}
	}
	for _, script := range hostScripts(host, "nbstat") {
		if _, m, v := parseNbstat(script); m != "" {
			return m, v, IdentitySourceNbstat
		}
	}
	return "", "", ""
}

// smb-os-discovery and nbstat are host-level scripts, so their output is
// copied onto every SMB port of the host (see hostResultFromNmapHost) -
// which means the same text appears several times and any one copy will
// do. Collected rather than taking the first so a port whose copy is
// empty cannot mask a populated one.
func hostScripts(host *HostResult, id string) []string {
	var out []string
	for _, port := range host.Ports {
		for _, script := range port.ExtraScripts {
			if script.ID == id && strings.TrimSpace(script.Output) != "" {
				out = append(out, script.Output)
			}
		}
	}
	return out
}

// The certificate an RDP service presents, which rdptls.go captures for
// every port isRDPPort classifies. Matched by port against the host's own
// RDP ports rather than by assuming 3389, since the certificate carries
// only the port it was taken from.
func hostnameFromRDPCertificate(host *HostResult) string {
	rdpPorts := map[int]bool{}
	for _, port := range host.Ports {
		if isRDPPort(port) {
			rdpPorts[port.Port] = true
		}
	}
	for _, cert := range host.TLSCertificates {
		if !rdpPorts[cert.Port] {
			continue
		}
		cn := strings.TrimSpace(cert.SubjectCN)
		if plausibleHostname(cn) {
			return cn
		}
	}
	return ""
}

// Real output, from a live host:
//
//	OS: Windows 6.1 (Samba 4.22.10)
//	Computer name: filer02
//	NetBIOS computer name: FILER02\x00
//	Domain name:
//	FQDN: filer02
//	System time: 2026-09-25T11:13:17+02:00
//
// Note what that shows: the FQDN field holds the *short* name when the
// machine is not domain-joined, because nmap builds it from computer name
// plus an empty domain. So a dot is the test for whether it is worth
// preferring, not the field name.
func hostnameFromSMBOSDiscovery(output string) string {
	fields := parseIndentedFields(output)
	if fqdn := fields["fqdn"]; strings.Contains(fqdn, ".") && plausibleHostname(fqdn) {
		return fqdn
	}
	for _, key := range []string{"computer name", "netbios computer name", "fqdn"} {
		value := cleanNetBIOSValue(fields[key])
		if plausibleHostname(value) {
			return value
		}
	}
	return ""
}

// Real output, from a live host:
//
//	NetBIOS name: FILER02, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
//	Names:
//	  FILER02<00>          Flags: <unique><active>
//
// The MAC is genuinely absent there - Samba does not answer with one -
// which is why this returns it separately rather than assuming a name
// implies an address.
func parseNbstat(output string) (name string, mac string, vendor string) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "NetBIOS name:") {
			continue
		}
		for _, part := range strings.Split(trimmed, ",") {
			part = strings.TrimSpace(part)
			key, value, ok := strings.Cut(part, ":")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			switch key {
			case "netbios name":
				if candidate := cleanNetBIOSValue(value); plausibleHostname(candidate) {
					name = candidate
				}
			case "netbios mac":
				// The value here is "XX:XX:… (Vendor)" or the literal
				// "<unknown> (unknown)".
				if m, v := macFromScriptOutput(part); m != "" {
					mac, vendor = m, v
				}
			}
		}
		break
	}
	return name, mac, vendor
}

var macVendorPattern = regexp.MustCompile(`\(([^)]+)\)`)

func macFromScriptOutput(output string) (string, string) {
	match := macPattern.FindString(output)
	if match == "" || !plausibleMAC(match) {
		return "", ""
	}
	mac := strings.ToUpper(match)
	// The vendor nmap resolved for it, when it managed to - "(unknown)"
	// is its own way of saying it did not.
	rest := output[strings.Index(output, match)+len(match):]
	if v := macVendorPattern.FindStringSubmatch(rest); len(v) == 2 {
		vendor := strings.TrimSpace(v[1])
		if vendor != "" && !strings.EqualFold(vendor, "unknown") {
			return mac, vendor
		}
	}
	return mac, ""
}

// "  Computer name: filer02" -> fields["computer name"] = "filer02".
// Lower-cased keys, since nmap's own capitalisation is not something to
// depend on across versions.
func parseIndentedFields(output string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, seen := fields[key]; !seen {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

// nbstat and smb-os-discovery both pad NetBIOS names with a trailing NUL,
// which nmap renders literally as the four characters \x00.
func cleanNetBIOSValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, `\x00`)
	value = strings.TrimRight(value, "\x00")
	return strings.TrimSpace(value)
}
