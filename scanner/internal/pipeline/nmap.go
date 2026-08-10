package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Port []nmapPort `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []nmapOSMatch `xml:"osmatch"`
	} `xml:"os"`
	// HostScripts are NSE scripts nmap runs once per host rather than once
	// per port (e.g. "smb-enum-shares" - a single SMB session already
	// covers every share, so nmap doesn't repeat it per port) - a sibling
	// of <ports>, not nested inside any one <port> element.
	HostScripts []nmapScript `xml:"hostscript>script"`
}

// nmapAddress is one of possibly several <address> elements per host -
// nmap always reports the target's own address this way (addrtype="ipv4"
// or "ipv6" depending on the scan), and adds a second one with
// addrtype="mac" (plus a vendor OUI lookup) only when it resolved the host
// via ARP/NDP, i.e. the target is on the scanner's own local L2 segment.
type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapOSMatch struct {
	Name     string        `xml:"name,attr"`
	Accuracy string        `xml:"accuracy,attr"`
	Classes  []nmapOSClass `xml:"osclass"`
}

type nmapOSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapScriptTableElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapScriptTable struct {
	Elems []nmapScriptTableElem `xml:"elem"`
}

type nmapScript struct {
	ID     string            `xml:"id,attr"`
	Output string            `xml:"output,attr"`
	Tables []nmapScriptTable `xml:"table"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		OSType    string   `xml:"ostype,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		CPEs      []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

// RunNmap performs service detection and banner grabbing (via the NSE
// script "banner") as well as a best-effort attempt to read SSH host keys
// (NSE script "ssh-hostkey") for the ports discovered by masscan on a
// single host. When running as root, it also attempts OS/device-type
// fingerprinting (-O).
//
// Also runs "ftp-anon" (checks whether anonymous/guest FTP login is
// allowed and, if so, lists the root directory) and "smb-enum-shares"
// (lists SMB shares visible over an anonymous/guest session). Both are in
// nmap's own "safe" script category - the same non-intrusive class as
// "banner" - and, like every NSE script here, are unconditionally part of
// every scan rather than a separate opt-in flag: nmap's own script
// portrule/hostrule matching already means ftp-anon only ever fires
// against a port it classifies as FTP and smb-enum-shares only against a
// host with an SMB port among the ones actually being scanned, so there's
// no extra gating needed on our side. Both stay silent (empty output) when
// the target requires real credentials - this only ever surfaces what's
// already reachable without any credentials at all, never attempts to
// guess or brute-force one.
//
// "smb-os-discovery" and "nbstat" are two more host-level scripts riding
// the same SMB session as smb-enum-shares - OS version/computer name/
// domain/workgroup (smb-os-discovery) and the NetBIOS name/domain
// (nbstat), both useful asset-identification signal independent of
// whether -O's OS fingerprint (root-only, see below) ran or matched
// anything. Unlike smb-enum-shares, neither gets its own PortResult
// field - hostResultFromNmapHost's host-script loop copies any
// HostScripts entry that isn't smb-enum-shares itself into
// PortResult.ExtraScripts on every port isSMBPort classifies, the same
// generic per-port mechanism the rest of this batch already uses, just
// applied at host-script granularity instead of per-port. Both stay
// silent under the same "requires real credentials" condition as
// smb-enum-shares, for the same reason (one shared SMB session).
//
// "smb-protocols" (which SMB dialects the server negotiates - whether
// legacy SMBv1 is still enabled, a real risk indicator given SMBv1's
// EternalBlue history) and "smb-security-mode"/"smb2-security-mode"
// (whether message signing is required, another real security-posture
// signal) round out the SMB group - all captured the same generic way
// as smb-os-discovery/nbstat above, whether nmap treats a given one as
// host-level or per-port (the capture logic handles both without
// needing to know in advance which).
//
// A second batch of read-only, no-credentials-needed "safe" scripts is
// also always included - a few more listing scripts in the same spirit as
// ftp-anon/smb-enum-shares ("nfs-showmount" for NFS exports,
// "rsync-list-modules" for rsync modules, "ldap-rootdse" for an anonymous
// LDAP bind's root DSE), plus a group that checks whether various common
// database/service daemons are reachable with no authentication at all -
// "mongodb-info"/"mongodb-databases", "redis-info", "mysql-info"
// (MySQL was a real gap in this group - one of the most common database
// engines, and its own info-gathering script needs no credentials, same
// as the others here), "memcached-info" (another commonly-left-open
// data store, same no-auth-needed reasoning), "oracle-tns-version"
// (decodes the version number an Oracle TNS listener's banner reports,
// no credentials needed to read it),
// "docker-version", "couchdb-databases", "cassandra-info" (there is no
// equivalent official NSE script for Elasticsearch - "http-elasticsearch"
// was briefly listed here but doesn't actually exist in nmap's script
// library, which made the NSE script engine refuse to start at all
// ("did not match a category, filename, or directory") and broke nmap
// enrichment for every host in every scan; the only real Elasticsearch
// script nmap ships, "http-vuln-cve2015-1427", checks one specific 2015 RCE
// rather than safely reading exposed info the way the others here do, so
// it isn't a fit for this group either). None of these
// get their own PortResult field the way ftp-anon/smb-enum-shares do -
// see PortResult.ExtraScripts, which hostResultFromNmapHost populates
// generically for any script id it doesn't otherwise recognize, so adding
// another script to this list later doesn't need a new struct field.
//
// "smtp-open-relay" is the one script here that isn't purely passive: it
// actively sends a handful of test messages through the target SMTP
// server to determine whether it relays mail for third parties (the
// classic open-relay misconfiguration check). Still non-destructive and
// still nmap's own "safe" category, but worth calling out explicitly -
// unlike everything else on this list, a successful check has a real
// side effect (the target server actually attempts to relay nmap's test
// messages), not just a read.
//
// "http-methods" (a per-port script, fires on whatever port nmap
// classifies as HTTP) reports which HTTP methods a server allows
// (GET/POST/PUT/DELETE/etc, and whether OPTIONS is even honest about
// them) - genuinely free to add here, same as the rest of this batch:
// it already falls into hostResultFromNmapHost's default case (any
// script id not otherwise special-cased goes into ExtraScripts), so
// adding it needed nothing beyond its name in --script.
//
// The same "just add the name" treatment applies to five more per-port
// scripts added alongside it: "http-auth" (the HTTP auth scheme/realm a
// server requires - notably, this is often the *only* signal available
// for a server behind HTTP Basic Auth, since that exact condition is
// also what silently prevents a gowitness screenshot, see the gowitness
// stage's own doc comment below), "http-git" (an exposed ".git"
// directory in the web root - a genuinely common, serious real-world
// finding, source disclosure via a forgotten deployment artifact),
// "rdp-ntlm-info" (hostname/domain/OS build leaked via RDP's own NTLM
// negotiation, no credentials needed), "rdp-enum-encryption" (which
// security layer/encryption level an RDP server allows - directly
// explains the RDP screenshot stage's own documented NLA-only
// limitation below, rather than just being a mystery when a screenshot
// never appears), and "ssh2-enum-algos"/"sshv1" (the SSH algorithms on
// offer, and whether the obsolete SSHv1 protocol is still enabled -
// rounds out ssh-hostkey with the same kind of protocol-security-
// posture signal smb-protocols/smb-security-mode give for SMB above).
//
// "rpcinfo" (lists every program registered with the target's RPC
// portmapper - relevant beyond just NFS, since any RPC-based service on
// the host shows up here) and "msrpc-enum" (queries a Windows MSRPC
// endpoint mapper for its own list of mapped services) round out the
// enumeration-listing group in the same spirit as nfs-showmount/
// rsync-list-modules/ldap-rootdse above - both are portrule-matched
// against whatever port nmap classifies as the relevant service
// (rpcbind/msrpc), so again nothing beyond the script name was needed.
//
// ssh-hostkey is best-effort: nmap's ssh2 NSE library doesn't support
// modern KEX algorithms (e.g. curve25519-sha256), so the script returns no
// host key for servers that only offer modern KEX methods by default (e.g.
// stock OpenSSH 9.9+/10) - confirmed via manual testing. It still works
// against older/classically configured SSH servers.
//
// -O is also best-effort, for a harder reason: nmap refuses to run at all
// with -O unless the process's effective UID is 0 ("QUITTING!", not just a
// skipped OS scan) - cap_net_raw/cap_net_admin (what setcap grants, and all
// the rest of this pipeline needs) is not enough, confirmed via manual
// testing. Since scanner deployments following this project's own setcap
// instructions are deliberately not root, -O is only added when we detect
// we're actually running as root; everything else in this function keeps
// working either way.
//
// --privileged is always passed: nmap's own internal check for "do I have
// raw-socket access" (used to decide between a raw SYN scan and a plain
// TCP connect scan when not running as root) can incorrectly conclude
// it doesn't, even when cap_net_raw/cap_net_admin is genuinely set and
// working - confirmed via manual testing in a capability-based (non-root)
// environment where nmap silently fell back to a connect scan, finding
// ports/services fine but never resolving/reporting the target's MAC
// address (applyMACAddress below then has nothing to read), and adding
// --privileged fixed it immediately. This is safe unconditionally: masscan
// already requires the same raw-socket capability just to run at all
// (RunMasscan below), so if this function is reached with any ports to
// scan, that capability is already known to be present.
func RunNmap(ctx context.Context, binPath, ip string, ports []PortResult) (*HostResult, error) {
	if len(ports) == 0 {
		return &HostResult{IP: ip}, nil
	}

	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = strconv.Itoa(p.Port)
	}

	args := []string{
		"-Pn", "-R", "--privileged",
		"-sV", "--script=banner,ssh-hostkey,ftp-anon,smb-enum-shares," +
			"smb-os-discovery,nbstat,smb-protocols,smb-security-mode,smb2-security-mode," +
			"nfs-showmount,rsync-list-modules,ldap-rootdse," +
			"mongodb-info,mongodb-databases,redis-info,mysql-info,memcached-info,oracle-tns-version," +
			"docker-version,couchdb-databases,cassandra-info,smtp-open-relay," +
			"http-methods,http-auth,http-git," +
			"rdp-ntlm-info,rdp-enum-encryption,ssh2-enum-algos,sshv1," +
			"rpcinfo,msrpc-enum",
	}
	if os.Geteuid() == 0 {
		args = append(args, "-O")
	}
	// nmap requires -6 to scan an IPv6 literal target at all - without it,
	// it either errors or misinterprets the argument as a hostname.
	// Detected here (rather than threaded through as a parameter) so this
	// stays correct regardless of which caller/path reached it.
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		args = append(args, "-6")
	}
	args = append(args,
		"-p", strings.Join(portList, ","),
		"-oX", "-",
		ip,
	)
	run, err := runNmapAndParse(ctx, binPath, args, ip)
	if err != nil {
		return nil, err
	}
	if len(run.Hosts) == 0 {
		return &HostResult{IP: ip}, nil
	}
	return hostResultFromNmapHost(ip, run.Hosts[0]), nil
}

// isSMBPort decides, based on the service name reported by nmap (with a
// port heuristic as fallback), whether a port is SMB - used to decide
// which of a host's ports "smb-enum-shares" output (a host-level script,
// not tied to any one port - see nmapHost.HostScripts) gets copied onto.
func isSMBPort(p PortResult) bool {
	name := strings.ToLower(p.ServiceName)
	if strings.Contains(name, "microsoft-ds") || strings.Contains(name, "netbios-ssn") || strings.Contains(name, "smb") {
		return true
	}
	return p.Port == 445 || p.Port == 139
}

// hostResultFromNmapHost builds a *HostResult from one already-parsed
// <host> element - split out from RunNmap so the parsing logic itself is
// unit-testable against a hand-built nmapHost, without needing a real
// nmap binary (same reasoning as discoveredFromNmapRun below).
func hostResultFromNmapHost(ip string, host nmapHost) *HostResult {
	result := &HostResult{IP: ip}
	for _, hn := range host.Hostnames.Hostname {
		if hn.Type == "PTR" || result.Hostname == "" {
			result.Hostname = hn.Name
		}
	}

	applyBestOSMatch(result, host.OS.Matches)
	applyMACAddress(result, host.Addresses)

	var smbShares string
	var smbHostExtraScripts []NSEScript
	for _, s := range host.HostScripts {
		switch s.ID {
		case "smb-enum-shares":
			smbShares = s.Output
		default:
			// smb-os-discovery, nbstat, and any future host-level SMB
			// script - same "capture generically, apply to every SMB
			// port" treatment as smb-enum-shares gets for its own
			// dedicated field, just riding PortResult.ExtraScripts
			// instead. Empty output (e.g. the session needed real auth)
			// is skipped, same as the per-port default case below.
			if s.Output != "" {
				smbHostExtraScripts = append(smbHostExtraScripts, NSEScript{ID: s.ID, Output: s.Output})
			}
		}
	}

	for _, p := range host.Ports.Port {
		banner := ""
		ftpAnonListing := ""
		var sshHostKeys []SSHHostKey
		var extraScripts []NSEScript
		for _, s := range p.Scripts {
			switch s.ID {
			case "banner":
				banner = s.Output
			case "ssh-hostkey":
				sshHostKeys = parseSSHHostKeys(s.Tables)
			case "ftp-anon":
				ftpAnonListing = s.Output
			default:
				// Anything else in the --script list (nfs-showmount,
				// rsync-list-modules, ldap-rootdse, the open-database
				// checks, and any script added here in the future) - see
				// PortResult.ExtraScripts. Empty output (script ran but
				// found nothing, e.g. the target required real auth) is
				// skipped rather than stored as a blank entry.
				if s.Output != "" {
					extraScripts = append(extraScripts, NSEScript{ID: s.ID, Output: s.Output})
				}
			}
		}
		pr := PortResult{
			Port:           p.PortID,
			Protocol:       p.Protocol,
			State:          p.State.State,
			ServiceName:    p.Service.Name,
			ServiceProduct: p.Service.Product,
			ServiceVersion: p.Service.Version,
			ExtraInfo:      p.Service.ExtraInfo,
			OSType:         p.Service.OSType,
			Tunnel:         p.Service.Tunnel,
			CPEs:           p.Service.CPEs,
			Banner:         banner,
			SSHHostKeys:    sshHostKeys,
			FTPAnonListing: ftpAnonListing,
			ExtraScripts:   extraScripts,
		}
		if isSMBPort(pr) {
			if smbShares != "" {
				pr.SMBShares = smbShares
			}
			if len(smbHostExtraScripts) > 0 {
				pr.ExtraScripts = append(pr.ExtraScripts, smbHostExtraScripts...)
			}
		}
		result.Ports = append(result.Ports, pr)
	}

	return result
}

// runNmapAndParse runs binPath with args, capturing stdout (nmap's own -oX
// XML output) and unmarshaling it. Shared by RunNmap and RunNmapDiscovery
// below so the exec/XML-parsing boilerplate isn't duplicated between the
// two - they differ only in which args they build and what they do with
// the resulting *nmapRun. targetDesc is just for the error message (a
// single ip for RunNmap, the whole target list for RunNmapDiscovery).
func runNmapAndParse(ctx context.Context, binPath string, args []string, targetDesc string) (*nmapRun, error) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap failed for %s: %w (stderr: %s)", targetDesc, err, stderr.String())
	}

	var run nmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &run); err != nil {
		return nil, fmt.Errorf("parsing nmap xml for %s: %w", targetDesc, err)
	}
	return &run, nil
}

// RunNmapDiscovery is the IPv6 target path's stand-in for RunMasscan -
// masscan has no IPv6 scanning capability at all, so this uses nmap itself
// as the discovery engine for one or more explicit IPv6 addresses (nmap
// natively accepts multiple target arguments in one invocation and returns
// one <host> element per target, so this never needs to shell out per
// address). Deliberately omits -sV/scripts/-O - this is a bare SYN
// port-discovery pass, mirroring masscan's own minimal contract (only
// Port/Protocol/State are meaningful; RunNmap runs next, unchanged except
// for -6, to enrich whatever this step found open with service/version/
// banner/OS info - the same two-stage split the IPv4 path already has).
// Only ports nmap reports as "open" are kept, matching masscan's own
// behavior of only ever reporting open ports, never closed/filtered ones.
func RunNmapDiscovery(ctx context.Context, binPath, portSpec string, ips []string) (map[string][]PortResult, error) {
	args := []string{
		"-6", "-Pn", "--privileged", "-sS",
		"-p", portSpec,
		"-oX", "-",
	}
	args = append(args, ips...)

	run, err := runNmapAndParse(ctx, binPath, args, strings.Join(ips, ","))
	if err != nil {
		return nil, err
	}
	return discoveredFromNmapRun(run), nil
}

// discoveredFromNmapRun converts a parsed nmap discovery run into the same
// map[string][]PortResult shape RunMasscan produces - only Port/Protocol/
// State, and only ports nmap reports "open" (masscan itself never reports
// closed/filtered ports, so neither does this). Split out from
// RunNmapDiscovery so the conversion itself is unit-testable against a
// canned *nmapRun without needing a real nmap binary.
func discoveredFromNmapRun(run *nmapRun) map[string][]PortResult {
	discovered := make(map[string][]PortResult)
	for _, host := range run.Hosts {
		ip := ""
		for _, a := range host.Addresses {
			if a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		for _, p := range host.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			discovered[ip] = append(discovered[ip], PortResult{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
			})
		}
	}
	return discovered
}

// applyBestOSMatch fills in result's OS/device-type fields from nmap's
// osmatch list. nmap sorts osmatch entries by descending accuracy, so the
// first one is its best guess; osclass gives the structured type/vendor/
// family nmap itself uses (e.g. type="switch", osfamily="Windows"). A nil
// or empty list leaves result unchanged.
func applyBestOSMatch(result *HostResult, matches []nmapOSMatch) {
	if len(matches) == 0 {
		return
	}
	best := matches[0]
	result.OSName = best.Name
	result.OSAccuracy, _ = strconv.Atoi(best.Accuracy)
	if len(best.Classes) > 0 {
		result.OSFamily = best.Classes[0].OSFamily
		result.OSVendor = best.Classes[0].Vendor
		result.DeviceType = best.Classes[0].Type
	}
}

// applyMACAddress fills in result's MAC fields from nmap's <address>
// elements, if one with addrtype="mac" is present - only the case when
// nmap resolved the host via ARP (i.e. it's on the scanner's own local L2
// segment). Leaves result unchanged otherwise.
func applyMACAddress(result *HostResult, addresses []nmapAddress) {
	for _, a := range addresses {
		if a.AddrType == "mac" {
			result.MACAddress = a.Addr
			result.MACVendor = a.Vendor
			return
		}
	}
}

// parseSSHHostKeys converts the <table> elements returned by nmap's
// ssh-hostkey script (one per host key type) into SSHHostKey values. The
// MD5 fingerprint comes directly from nmap; the SHA-256 fingerprint is
// computed ourselves from the base64-encoded public key blob (nmap's
// structured output doesn't provide one), in the same format that e.g.
// "ssh-keygen -lf" would display.
func parseSSHHostKeys(tables []nmapScriptTable) []SSHHostKey {
	var keys []SSHHostKey
	for _, t := range tables {
		values := make(map[string]string, len(t.Elems))
		for _, e := range t.Elems {
			values[e.Key] = e.Value
		}

		keyType := values["type"]
		if keyType == "" {
			continue
		}

		bits, _ := strconv.Atoi(values["bits"])

		fingerprintSHA256 := ""
		if keyBlob, err := base64.StdEncoding.DecodeString(values["key"]); err == nil {
			sum := sha256.Sum256(keyBlob)
			fingerprintSHA256 = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		}

		keys = append(keys, SSHHostKey{
			KeyType:           keyType,
			Bits:              bits,
			FingerprintMD5:    strings.ToLower(values["fingerprint"]),
			FingerprintSHA256: fingerprintSHA256,
		})
	}
	return keys
}
