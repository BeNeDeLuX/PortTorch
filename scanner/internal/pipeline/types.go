package pipeline

import "time"

// SSHHostKey describes an SSH host key read by nmap's "ssh-hostkey"
// script. Best-effort: nmap's ssh2 NSE library doesn't support modern KEX
// algorithms (e.g. curve25519-sha256), so this script returns no host key
// for servers that only offer modern KEX methods (e.g. stock OpenSSH
// 9.9+/10 without an explicitly extended KexAlgorithms config) - this is
// an nmap limitation, not a bug here.
type SSHHostKey struct {
	KeyType           string
	Bits              int
	FingerprintMD5    string
	FingerprintSHA256 string
}

// PortResult describes a single open port including the service/banner
// information determined by nmap.
type PortResult struct {
	Port           int
	Protocol       string
	State          string
	ServiceName    string
	ServiceProduct string
	ServiceVersion string
	// ExtraInfo, OSType and CPEs come from nmap's version-detection engine
	// (the <service> element's extrainfo/ostype attributes and its <cpe>
	// children) - CPEs are standardized Common Platform Enumeration
	// strings, e.g. "cpe:/a:openbsd:openssh:8.4".
	ExtraInfo   string
	OSType      string
	CPEs        []string
	Banner      string
	SSHHostKeys []SSHHostKey
	// Tunnel is nmap's own <service tunnel="..."> attribute, set to "ssl"
	// when nmap's version detection identified the app-layer protocol
	// through a TLS handshake - more reliable than guessing TLS from the
	// service name or port number alone (see isHTTPPort/isTLSPort).
	Tunnel string
	// FTPAnonListing is nmap's "ftp-anon" NSE script output (best-effort,
	// only ever populated for a port nmap itself classifies as FTP) -
	// empty unless anonymous/guest FTP login is actually allowed, in which
	// case it's nmap's own human-readable report of that plus a directory
	// listing of what's exposed.
	FTPAnonListing string
	// SMBShares is nmap's "smb-enum-shares" NSE script output - a host-level
	// script (one SMB session covers every share), copied onto every port
	// isSMBPort classifies for this host rather than attached to a single
	// port, since the underlying SMB session isn't itself port-specific.
	// Empty unless the target allows an anonymous/guest SMB session, same
	// best-effort "absence means access was denied" reasoning as
	// FTPAnonListing.
	SMBShares string
	// ExtraScripts is every other NSE script result nmap produced for this
	// port that doesn't get its own dedicated field above - a growing long
	// tail of read-only enumeration scripts (NFS/rsync/LDAP listings, open
	// database instances like MongoDB/Redis/Docker/CouchDB/Cassandra) that
	// don't each need their own struct field and DB column,
	// unlike banner/ssh-hostkey/ftp-anon/smb-enum-shares which are common
	// and important enough to get dedicated display treatment. Adding a
	// new script to this category is just adding its id to RunNmap's
	// --script list - hostResultFromNmapHost captures any script id it
	// doesn't already recognize into this slice automatically.
	ExtraScripts []NSEScript
}

// NSEScript is the id/output of one NSE script result that doesn't have
// its own dedicated field on PortResult - see ExtraScripts above.
type NSEScript struct {
	ID     string
	Output string
}

// Screenshot describes a screenshot of an HTTP(S) page taken by gowitness.
// ImagePath lives in a temporary directory unique per screenshot - the
// caller is responsible for cleanup (os.RemoveAll(filepath.Dir(ImagePath)))
// after submitting it to the ingest API.
type Screenshot struct {
	Port       int
	URL        string
	ImagePath  string
	HTTPStatus int
	PageTitle  string

	// TLS certificate and technology detection, as already provided by
	// gowitness. All fields stay empty if not connected via TLS or if no
	// technology was detected.
	TLSProtocol  string
	TLSCipher    string
	TLSSubject   string
	TLSIssuer    string
	TLSValidFrom string
	TLSValidTo   string
	Technologies []string

	// Headers holds the HTTP response headers gowitness captured for the
	// final response. A map collapses repeated header names (e.g. multiple
	// Set-Cookie lines) to their last value - acceptable for the purely
	// informational display this feeds.
	Headers map[string]string

	// OCRText is extracted from the screenshot via Tesseract (ocr.go) -
	// empty if tesseract isn't installed or recognition failed, since
	// this is best-effort like everything else in this stage.
	OCRText string
}

// RDPScreenshot describes a screenshot of an RDP login/connection screen
// taken via Xvfb+xfreerdp+ImageMagick. Same cleanup rule as Screenshot: the
// caller removes filepath.Dir(ImagePath) after submission.
type RDPScreenshot struct {
	Port      int
	ImagePath string
	OCRText   string
}

// TLSCertificate describes the server certificate read via a real TLS
// handshake (crypto/tls, no external dependency) on any TLS-carrying port -
// not just HTTP(S), but also e.g. IMAPS/SMTPS/LDAPS.
type TLSCertificate struct {
	Port               int
	SubjectCN          string
	IssuerCN           string
	SANs               []string
	NotBefore          time.Time
	NotAfter           time.Time
	FingerprintSHA256  string
	SignatureAlgorithm string
	SelfSigned         bool

	// TLSVersion and CipherSuite describe the negotiated handshake (e.g.
	// "TLS 1.3", "TLS_AES_256_GCM_SHA384"), not the certificate itself.
	// KeyAlgorithm/KeyBits describe the certificate's public key (e.g.
	// "RSA", 2048).
	TLSVersion   string
	CipherSuite  string
	KeyAlgorithm string
	KeyBits      int
}

// NucleiFinding describes one matched nuclei template against an HTTP(S)
// port - a web-application-level finding (exposed panel/config, known CVE,
// misconfiguration, tech fingerprint) distinct from nmap's own NSE-script
// output on PortResult. Reference/Tags/CurlCommand mirror nuclei's own
// -jsonl output fields (captured from a real run - see nuclei.go's doc
// comment) - Reference and Description are frequently absent entirely for
// a given template, not just empty, so both are best-effort like everything
// else best-effort in this pipeline.
type NucleiFinding struct {
	Port        int
	TemplateID  string
	Name        string
	Severity    string
	MatchedAt   string
	Description string
	Reference   []string
	Tags        []string
	CurlCommand string
}

// HostResult aggregates all results for a host.
type HostResult struct {
	IP       string
	Hostname string

	// OS/device-type fingerprint from nmap's -O (root-only, see RunNmap) -
	// OSName is nmap's free-text best guess (e.g. "Linux 5.0 - 6.2"),
	// OSFamily/OSVendor/DeviceType are its structured classification (e.g.
	// osfamily="Windows", vendor="Cisco", type="switch"). All empty if OS
	// detection wasn't run or found no match.
	OSName     string
	OSFamily   string
	OSVendor   string
	DeviceType string
	OSAccuracy int

	// MACAddress/MACVendor come from nmap's ARP resolution and are only
	// ever populated for targets on the scanner's own local L2 segment -
	// MAC addresses aren't visible at all across a routed hop, which is
	// most targets in a typical internal network scan. Both empty
	// whenever nmap has no MAC to report, not just when the host is
	// remote - this is best-effort, not a guarantee.
	MACAddress string
	MACVendor  string

	Ports           []PortResult
	Screenshots     []Screenshot
	RDPScreenshots  []RDPScreenshot
	TLSCertificates []TLSCertificate
	NucleiFindings  []NucleiFinding
}

// ScanResult is the overall result of a scan run through
// masscan+nmap+gowitness/rdp screenshots.
type ScanResult struct {
	TargetSpec string
	PortSpec   string
	Hosts      []HostResult
}
