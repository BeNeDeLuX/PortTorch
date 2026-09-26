package pipeline

import (
	"regexp"
	"strings"
)

// Reading a Windows host's exact build out of what the scan already saw.
//
// nmap's own -O fingerprint is too coarse to answer "which version is
// this": for Windows it typically reports a family spanning several
// releases at once. The precise answer comes from somewhere else
// entirely - NTLM. Sending an incomplete authentication request with null
// credentials makes Windows answer with an NTLMSSP message that carries
// its own Product_Version, e.g. "10.0.17763", which identifies the
// release exactly.
//
// nmap ships eight scripts that do this against different services, and
// all of them are in the batch (see RunNmap). rdp-ntlm-info is the one
// that fires most often on an internal network - and it works precisely
// where the RDP *screenshot* cannot, since it needs the NLA that defeats
// the screenshot path.
//
// Only the build number is extracted here. What "10.0.17763" is called,
// and whether it is still supported, is deliberately not decided in the
// scanner: that mapping gains entries and its support dates pass with
// time, so it lives on the webserver where updating it is a deploy rather
// than a scanner release across the fleet. The scanner reports the fact;
// the webserver interprets it.

// Every *-ntlm-info script nmap ships, confirmed against a real nmap 7.95
// with --script-help rather than assumed - a name that does not resolve
// aborts nmap for every host in the scan, which this codebase has a
// documented incident for.
var ntlmInfoScripts = []string{
	"rdp-ntlm-info",
	"http-ntlm-info",
	"smtp-ntlm-info",
	"imap-ntlm-info",
	"pop3-ntlm-info",
	"nntp-ntlm-info",
	"telnet-ntlm-info",
	"ms-sql-ntlm-info",
}

// "10.0.17763". Anchored so a version embedded in prose cannot be
// mistaken for the field's own value.
var productVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// deriveWindowsBuild returns the build and the script it came from, or
// empty strings when no NTLM exchange produced one.
//
// The scripts are tried in the order above rather than "first output
// wins" across the host, so a host answering on several services reports
// a stable source rather than one that changes with port ordering.
func deriveWindowsBuild(host *HostResult) (string, string) {
	for _, script := range ntlmInfoScripts {
		for _, output := range hostScripts(host, script) {
			if build := productVersionFrom(output); build != "" {
				return build, script
			}
		}
	}
	return "", ""
}

func productVersionFrom(output string) string {
	value := strings.TrimSpace(parseIndentedFields(output)["product_version"])
	if productVersionPattern.MatchString(value) {
		return value
	}
	return ""
}

// The FQDN the same NTLM message carries - "W16GA-SRV01.W2016.lab" in
// nmap's own documented example. Better than anything SMB offers, which
// is why it sits above smb-os-discovery in the hostname chain: a
// domain-joined machine reports its full name here even when SMB1 is off
// and smb-os-discovery returns nothing at all.
func hostnameFromNTLM(host *HostResult) (string, string) {
	for _, script := range ntlmInfoScripts {
		for _, output := range hostScripts(host, script) {
			fields := parseIndentedFields(output)
			// DNS_Computer_Name is the FQDN; the NetBIOS name is the
			// short form and only worth having if the FQDN is absent.
			for _, key := range []string{"dns_computer_name", "netbios_computer_name"} {
				candidate := cleanNetBIOSValue(fields[key])
				if plausibleHostname(candidate) {
					return candidate, script
				}
			}
		}
	}
	return "", ""
}
