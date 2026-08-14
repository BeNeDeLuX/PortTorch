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
	MasscanRate int    `yaml:"masscanRate"`
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

	// ListenAddr and ControlAPIToken are only used by the "serve"
	// subcommand, which accepts scans via REST API instead of the TUI.
	ListenAddr      string `yaml:"listenAddr,omitempty"`
	ControlAPIToken string `yaml:"controlApiToken,omitempty"`

	// PollIntervalSeconds controls how often "scanner serve" asks the
	// webserver for pending scan requests (rescan button/schedules).
	PollIntervalSeconds int `yaml:"pollIntervalSeconds"`

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

		ListenAddr:          ":9090",
		PollIntervalSeconds: 15,

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

	if cfg.SubmitQueueDir == "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}
		cfg.SubmitQueueDir = filepath.Join(filepath.Dir(absPath), "submit-queue")
	}

	return &cfg, nil
}

// Pipeline builds the pipeline.Config from the scan-relevant fields.
func (c *Config) Pipeline() pipeline.Config {
	return pipeline.Config{
		MasscanPath:              c.MasscanPath,
		NmapPath:                 c.NmapPath,
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
	}
}
