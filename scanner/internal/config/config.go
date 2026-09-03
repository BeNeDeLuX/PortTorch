package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"porttorch/scanner/internal/pipeline"
)

// Config is the YAML configuration loaded by the scanner.
type Config struct {
	WebserverURL       string `yaml:"webserverUrl"`
	APIKey             string `yaml:"apiKey"`
	ServerCACertPath   string `yaml:"serverCaCertPath,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`

	MasscanPath string `yaml:"masscanPath"`
	NmapPath    string `yaml:"nmapPath"`
	// NmapSudo runs nmap as "sudo -n <nmapPath>". Set by install.sh
	// together with the argument-validating wrapper it points NmapPath
	// at, so the unprivileged service user can still use the two nmap
	// features that refuse to run for anyone but real root: -O
	// (OS/device fingerprinting) and -sS (which every UDP scan needs
	// alongside -sU). Defaults to false - an existing config that never
	// mentions it keeps invoking nmap exactly as before, just without
	// OS classification. See pipeline.NmapCmd.
	NmapSudo    bool `yaml:"nmapSudo"`
	MasscanRate int  `yaml:"masscanRate"`
	// MasscanRetries: masscan is a stateless SYN scanner, so a single lost
	// packet in either direction means a genuinely open port simply isn't
	// reported that run - retries resend the probe (1s apart) regardless
	// of whether a reply was already seen, trading a little extra time
	// for materially fewer false negatives on lossy/slow networks.
	MasscanRetries int `yaml:"masscanRetries"`
	Concurrency    int `yaml:"concurrency"`

	GowitnessPath            string `yaml:"gowitnessPath"`
	ChromePath               string `yaml:"chromePath,omitempty"`
	ScreenshotTimeoutSeconds int    `yaml:"screenshotTimeoutSeconds"`
	// ScreenshotWidth/ScreenshotHeight set gowitness's Chrome window size,
	// and so the resolution of the captured screenshot - higher than
	// gowitness's own 1280x720 default for a sharper image on the host
	// detail page's lightbox.
	ScreenshotWidth  int `yaml:"screenshotWidth"`
	ScreenshotHeight int `yaml:"screenshotHeight"`
	// GowitnessConcurrency is separate from (and defaults much lower
	// than) concurrency: each gowitness invocation spawns its own full
	// headless Chrome instance, so running several at once needs much
	// more CPU/RAM headroom than the same number of nmap processes -
	// reusing the general concurrency setting here can starve every
	// concurrent Chrome instance and make them all miss
	// screenshotTimeoutSeconds together.
	GowitnessConcurrency int `yaml:"gowitnessConcurrency"`

	XfreerdpPath              string `yaml:"xfreerdpPath"`
	XvfbPath                  string `yaml:"xvfbPath"`
	ImportPath                string `yaml:"importPath"`
	RDPScreenWidth            int    `yaml:"rdpScreenWidth"`
	RDPScreenHeight           int    `yaml:"rdpScreenHeight"`
	RDPConnectTimeoutSeconds  int    `yaml:"rdpConnectTimeoutSeconds"`
	RDPScreenshotDelaySeconds int    `yaml:"rdpScreenshotDelaySeconds"`
	// RDPConcurrency is separate from concurrency for the same reason as
	// gowitnessConcurrency - Xvfb+xfreerdp+import per screenshot is also
	// far heavier than an nmap process.
	RDPConcurrency int `yaml:"rdpConcurrency"`

	// TLSCertTimeoutSeconds controls the timeout for the real TLS
	// handshake used to read certificates (CN, validity, fingerprint) on
	// all ports detected as TLS-carrying.
	TLSCertTimeoutSeconds int `yaml:"tlsCertTimeoutSeconds"`

	// TesseractPath enables OCR text extraction on HTTP(S)/RDP
	// screenshots (best-effort - a missing binary just means no OCR text,
	// not a failed scan). Requires tesseract-ocr, e.g.
	// "sudo apt-get install -y tesseract-ocr".
	TesseractPath string `yaml:"tesseractPath"`

	// NucleiPath enables the web-vulnerability-scanning stage (best-effort
	// like gowitness/xfreerdp/tesseract - only ever invoked when a scan
	// request resolves a non-off nuclei profile, see
	// resolveNucleiProfile; a missing binary then just means that host's
	// nuclei sub-tasks fail individually, not a failed scan).
	NucleiPath           string `yaml:"nucleiPath"`
	NucleiTimeoutSeconds int    `yaml:"nucleiTimeoutSeconds"`
	// NucleiConcurrency is separate from (and defaults much lower than)
	// Concurrency, same reasoning as GowitnessConcurrency/RDPConcurrency -
	// each nuclei invocation walks its whole selected template set
	// against one target, far heavier than a single nmap process.
	NucleiConcurrency int `yaml:"nucleiConcurrency"`

	// ListenAddr and ControlAPIToken are only used by the "serve"
	// subcommand, which accepts scans via REST API instead of the TUI.
	ListenAddr      string `yaml:"listenAddr,omitempty"`
	ControlAPIToken string `yaml:"controlApiToken,omitempty"`

	// PollIntervalSeconds controls how often "scanner serve" asks the
	// webserver for pending scan requests (rescan button/schedules).
	PollIntervalSeconds int `yaml:"pollIntervalSeconds"`

	// MaxConcurrentScans is how many queued scan requests "scanner serve"
	// will work on at the same time. Defaults to 1, which is exactly the
	// behaviour that existed before this setting: the poll loop picked up
	// one request and did nothing else until it finished, so a wide or
	// UDP sweep could block every other queued request - including a
	// high-priority one - for hours.
	//
	// Raising it is genuinely a resource decision, not a free speedup:
	// each concurrent scan runs its own masscan/nmap plus its own
	// gowitness/nuclei worker pools (concurrency, gowitnessConcurrency,
	// ... are per-scan, not global), so two scans at once means twice the
	// processes and twice the bandwidth.
	MaxConcurrentScans int `yaml:"maxConcurrentScans"`

	// SubmitQueueDir holds host results that failed to submit to the
	// webserver (see internal/submitqueue) until they can be retried -
	// defaults to a "submit-queue" directory next to the config file
	// itself if left unset, so a normal install needs no extra
	// configuration for this to work.
	SubmitQueueDir string `yaml:"submitQueueDir,omitempty"`
	// RetryIntervalSeconds controls how often "scanner serve" retries
	// queued submissions in the background, independent of the scan-
	// request poll interval - "scan"/"menu" only ever drain the queue
	// once, at startup, since they have no ongoing loop to periodically
	// retry from.
	RetryIntervalSeconds int `yaml:"retryIntervalSeconds"`

	// ScanAuditLogPath is a permanent, append-only, local record of
	// every host this scanner has ever found (see internal/auditlog) -
	// independent of the webserver's own reachability or retention.
	// Defaults to a "scan-audit.jsonl" file next to the config file
	// itself if left unset, so a normal install needs no extra
	// configuration for this to work.
	ScanAuditLogPath string `yaml:"scanAuditLogPath,omitempty"`
}

func defaults() Config {
	return Config{
		MasscanPath:              "masscan",
		NmapPath:                 "nmap",
		MasscanRate:              1000,
		MasscanRetries:           2,
		Concurrency:              5,
		GowitnessPath:            "gowitness",
		ScreenshotTimeoutSeconds: 20,
		ScreenshotWidth:          1920,
		ScreenshotHeight:         1080,
		GowitnessConcurrency:     2,

		XfreerdpPath:              "xfreerdp3",
		XvfbPath:                  "Xvfb",
		ImportPath:                "import",
		RDPScreenWidth:            1920,
		RDPScreenHeight:           1080,
		RDPConnectTimeoutSeconds:  8,
		RDPScreenshotDelaySeconds: 8,
		RDPConcurrency:            2,

		TLSCertTimeoutSeconds: 8,
		TesseractPath:         "tesseract",

		NucleiPath:           "nuclei",
		NucleiTimeoutSeconds: 10,
		NucleiConcurrency:    2,

		ListenAddr:          ":9090",
		PollIntervalSeconds: 15,
		MaxConcurrentScans:  1,

		RetryIntervalSeconds: 60,
	}
}

// Load reads the YAML configuration file from path and applies defaults
// for unset fields.
func Load(path string) (*Config, error) {
	cfg := defaults()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if cfg.WebserverURL == "" {
		return nil, fmt.Errorf("config %s: webserverUrl is required", path)
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("config %s: apiKey is required", path)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	if cfg.SubmitQueueDir == "" {
		cfg.SubmitQueueDir = filepath.Join(filepath.Dir(absPath), "submit-queue")
	}
	if cfg.ScanAuditLogPath == "" {
		cfg.ScanAuditLogPath = filepath.Join(filepath.Dir(absPath), "scan-audit.jsonl")
	}
	// Clamped rather than rejected. A config that predates this field
	// simply keeps the default of 1 (yaml.Unmarshal only overwrites keys
	// the file actually has), so this only ever catches an explicit 0 or
	// a negative - where silently refusing to run any scan at all would
	// be a far worse failure than quietly meaning "one".
	if cfg.MaxConcurrentScans < 1 {
		cfg.MaxConcurrentScans = 1
	}

	return &cfg, nil
}

// Pipeline builds the pipeline.Config from the scan-relevant fields.
func (c *Config) Pipeline() pipeline.Config {
	return pipeline.Config{
		MasscanPath:              c.MasscanPath,
		NmapPath:                 c.NmapPath,
		NmapSudo:                 c.NmapSudo,
		MasscanRate:              c.MasscanRate,
		MasscanRetries:           c.MasscanRetries,
		Concurrency:              c.Concurrency,
		GowitnessPath:            c.GowitnessPath,
		ChromePath:               c.ChromePath,
		ScreenshotTimeoutSeconds: c.ScreenshotTimeoutSeconds,
		ScreenshotWidth:          c.ScreenshotWidth,
		ScreenshotHeight:         c.ScreenshotHeight,
		GowitnessConcurrency:     c.GowitnessConcurrency,

		XfreerdpPath:              c.XfreerdpPath,
		XvfbPath:                  c.XvfbPath,
		ImportPath:                c.ImportPath,
		RDPScreenWidth:            c.RDPScreenWidth,
		RDPScreenHeight:           c.RDPScreenHeight,
		RDPConnectTimeoutSeconds:  c.RDPConnectTimeoutSeconds,
		RDPScreenshotDelaySeconds: c.RDPScreenshotDelaySeconds,
		RDPConcurrency:            c.RDPConcurrency,

		TLSCertTimeoutSeconds: c.TLSCertTimeoutSeconds,
		TesseractPath:         c.TesseractPath,

		NucleiPath:           c.NucleiPath,
		NucleiTimeoutSeconds: c.NucleiTimeoutSeconds,
		NucleiConcurrency:    c.NucleiConcurrency,
	}
}
