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
		"-sV", "--script=banner,ssh-hostkey",
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

	host := run.Hosts[0]
	result := &HostResult{IP: ip}
	for _, hn := range host.Hostnames.Hostname {
		if hn.Type == "PTR" || result.Hostname == "" {
			result.Hostname = hn.Name
		}
	}

	applyBestOSMatch(result, host.OS.Matches)
	applyMACAddress(result, host.Addresses)

	for _, p := range host.Ports.Port {
		banner := ""
		var sshHostKeys []SSHHostKey
		for _, s := range p.Scripts {
			switch s.ID {
			case "banner":
				banner = s.Output
			case "ssh-hostkey":
				sshHostKeys = parseSSHHostKeys(s.Tables)
			}
		}
		result.Ports = append(result.Ports, PortResult{
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
		})
	}

	return result, nil
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
