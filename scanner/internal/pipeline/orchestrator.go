package pipeline

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config bundles the binary paths and run parameters needed by the
// pipeline. Shared by the TUI, REST API, and CLI.
type Config struct {
	MasscanPath string
	NmapPath    string
	MasscanRate int
	// MasscanRetries is masscan's own --retries - see RunMasscan's doc
	// comment for why a stateless SYN scanner benefits from resending
	// probes rather than relying on a single pass.
	MasscanRetries int
	Concurrency    int

	GowitnessPath            string
	ChromePath               string
	ScreenshotTimeoutSeconds int
	// ScreenshotWidth/ScreenshotHeight set gowitness's Chrome window size
	// (--chrome-window-x/-y), and so the resolution of the captured PNG -
	// default well above gowitness's own 1280x720 default for a sharper,
	// more readable screenshot on the host detail page's lightbox.
	ScreenshotWidth  int
	ScreenshotHeight int
	// GowitnessConcurrency is deliberately separate from (and defaults
	// much lower than) Concurrency: each gowitness invocation spawns its
	// own full headless Chrome instance, which is far heavier than an
	// nmap process. Running gowitnessConcurrency-many of those in true
	// parallel needs real CPU/RAM headroom - reusing Concurrency's higher
	// default here starved every concurrent Chrome instance of resources
	// and made them all miss ScreenshotTimeoutSeconds together, a real
	// failure pattern seen in practice (a scan with Concurrency=5 timed
	// out on 5 of 7 gowitness attempts, all started within milliseconds
	// of each other).
	GowitnessConcurrency int

	XfreerdpPath              string
	XvfbPath                  string
	ImportPath                string
	RDPScreenWidth            int
	RDPScreenHeight           int
	RDPConnectTimeoutSeconds  int
	RDPScreenshotDelaySeconds int
	// RDPConcurrency is separate from Concurrency for the same reason as
	// GowitnessConcurrency - Xvfb+xfreerdp+import per screenshot is also
	// far heavier than an nmap process.
	RDPConcurrency int

	TLSCertTimeoutSeconds int

	// TesseractPath enables OCR text extraction (ocr.go) on both HTTP(S)
	// and RDP screenshots - best-effort like gowitness/RDP themselves, so
	// a missing tesseract binary just means no OCR text, not a failed scan.
	TesseractPath string
}

func (c Config) tlsCertTimeout() time.Duration {
	return time.Duration(c.TLSCertTimeoutSeconds) * time.Second
}

func (c Config) withDefaults() Config {
	if c.MasscanPath == "" {
		c.MasscanPath = "masscan"
	}
	if c.NmapPath == "" {
		c.NmapPath = "nmap"
	}
	if c.MasscanRate <= 0 {
		c.MasscanRate = 1000
	}
	if c.MasscanRetries <= 0 {
		c.MasscanRetries = 2
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 5
	}
	if c.GowitnessPath == "" {
		c.GowitnessPath = "gowitness"
	}
	if c.ScreenshotTimeoutSeconds <= 0 {
		c.ScreenshotTimeoutSeconds = 20
	}
	if c.ScreenshotWidth <= 0 {
		c.ScreenshotWidth = 1920
	}
	if c.ScreenshotHeight <= 0 {
		c.ScreenshotHeight = 1080
	}
	if c.GowitnessConcurrency <= 0 {
		c.GowitnessConcurrency = 2
	}
	if c.XfreerdpPath == "" {
		c.XfreerdpPath = "xfreerdp3"
	}
	if c.XvfbPath == "" {
		c.XvfbPath = "Xvfb"
	}
	if c.ImportPath == "" {
		c.ImportPath = "import"
	}
	if c.RDPScreenWidth <= 0 {
		c.RDPScreenWidth = 1920
	}
	if c.RDPScreenHeight <= 0 {
		c.RDPScreenHeight = 1080
	}
	if c.RDPConnectTimeoutSeconds <= 0 {
		c.RDPConnectTimeoutSeconds = 8
	}
	if c.RDPScreenshotDelaySeconds <= 0 {
		c.RDPScreenshotDelaySeconds = 8
	}
	if c.RDPConcurrency <= 0 {
		c.RDPConcurrency = 2
	}
	if c.TLSCertTimeoutSeconds <= 0 {
		c.TLSCertTimeoutSeconds = 8
	}
	if c.TesseractPath == "" {
		c.TesseractPath = "tesseract"
	}
	return c
}

// ProgressFunc is called with status messages during a scan, e.g. to
// display them in the TUI or via the REST API.
type ProgressFunc func(stage string, message string)

func noopProgress(string, string) {}

// HostCompleteFunc is called once per host, as soon as nmap and every
// gowitness/RDP/TLS sub-task for that host's ports has finished (or
// failed) - independently of every other host, so a host with little or
// no follow-up work (e.g. only an SSH port) can be reported long before a
// slower host's screenshots finish. Callers use this to submit each
// host's results to the webserver immediately rather than waiting for
// the whole scan to finish - see client.SubmitHosts and friends. May be
// called concurrently from different goroutines for different hosts, so
// implementations must be safe for concurrent use.
type HostCompleteFunc func(HostResult)

func noopHostComplete(HostResult) {}

// RunScan runs the complete discovery -> nmap (+gowitness/RDP/TLS) pipeline
// for a target and a port spec. targetSpec is either an IPv4 single
// address/CIDR/"start-end" range (discovered via masscan) or - if it
// contains a ":" - a single IPv6 address or comma-separated list of them
// (discovered via nmap itself, since masscan has no IPv6 capability at all;
// an IPv6 CIDR/range is rejected outright rather than silently
// mishandled - see parseIPv6TargetList). excludes is the central exclude
// list (see client.Client.GetExcludes) and is applied before either
// discovery mechanism runs - callers should always fetch a fresh list
// rather than caching it, so an admin's most recent excludes take effect
// on the very next scan.
//
// masscan itself can't stream - it only reports its discoveries once the
// whole pass across the target range finishes, a hard limitation of the
// external tool, not a design choice here (nmap's own discovery pass in
// the IPv6 path has the same one-shot limitation, for the same reason: it
// only reports once the whole invocation finishes). Everything after that
// point (nmap, gowitness, RDP, TLS) already ran with per-host worker
// pools, so onHostComplete fires as soon as an individual host's own
// pipeline finishes rather than waiting for the slowest host in the batch
// - see hostTracker below for how completion is tracked across four
// concurrently-running stages instead of four sequential ones.
//
// probeHostnames (see client.Client.GetProbeHostnames) maps an IP to a
// manually-configured hostname to use instead of the bare IP for the TLS
// certificate probe's SNI and the gowitness screenshot URL - needed for
// targets that reject/misroute a bare-IP (no working SNI) connection, e.g.
// nginx-style virtual hosting. A nil map is safe: a missing entry just
// means "no override, use the IP" (today's unchanged behavior).
func RunScan(ctx context.Context, cfg Config, targetSpec, portSpec string, excludes Excludes, probeHostnames map[string]string, onProgress ProgressFunc, onHostComplete HostCompleteFunc) (*ScanResult, error) {
	cfg = cfg.withDefaults()
	if onProgress == nil {
		onProgress = noopProgress
	}
	if onHostComplete == nil {
		onHostComplete = noopHostComplete
	}

	effectivePortSpec, err := subtractPorts(portSpec, excludes.Ports)
	if err != nil {
		return nil, fmt.Errorf("applying port excludes: %w", err)
	}
	if effectivePortSpec == "" {
		onProgress("masscan", "all requested ports are excluded, nothing to scan")
		return &ScanResult{TargetSpec: targetSpec, PortSpec: portSpec}, nil
	}
	if effectivePortSpec != portSpec {
		onProgress("masscan", fmt.Sprintf("port excludes applied: %s -> %s", portSpec, effectivePortSpec))
	}

	var discovered map[string][]PortResult
	if strings.Contains(targetSpec, ":") {
		// masscan has no IPv6 scanning capability at all, so a colon in
		// targetSpec (never present in an IPv4 address/CIDR/range) routes
		// through nmap itself as the discovery engine instead - see
		// RunNmapDiscovery's doc comment for why this is a single/explicit-
		// list-of-addresses path only, not a CIDR/range sweep.
		ips, err := parseIPv6TargetList(targetSpec)
		if err != nil {
			return nil, err
		}

		var survivors []string
		for _, ip := range ips {
			if excluded, reason := isTargetExcluded(ip, excludes.IPs); excluded {
				onProgress("nmap", fmt.Sprintf("%s excluded (matches %s)", ip, reason))
				continue
			}
			survivors = append(survivors, ip)
		}
		if len(survivors) == 0 {
			onProgress("nmap", "every requested IPv6 target is excluded, nothing to scan")
			return &ScanResult{TargetSpec: targetSpec, PortSpec: portSpec}, nil
		}

		onProgress("nmap", fmt.Sprintf("scanning %s (ports %s) via nmap discovery (IPv6, masscan unsupported)", strings.Join(survivors, ","), effectivePortSpec))
		discovered, err = RunNmapDiscovery(ctx, cfg.NmapPath, effectivePortSpec, survivors)
		if err != nil {
			return nil, fmt.Errorf("nmap discovery stage: %w", err)
		}
		onProgress("nmap", fmt.Sprintf("found %d host(s) with open ports", len(discovered)))
	} else {
		onProgress("masscan", fmt.Sprintf("scanning %s (ports %s)", targetSpec, effectivePortSpec))
		var err error
		discovered, err = RunMasscan(ctx, cfg.MasscanPath, targetSpec, effectivePortSpec, excludes.IPs, cfg.MasscanRate, cfg.MasscanRetries)
		if err != nil {
			return nil, fmt.Errorf("masscan stage: %w", err)
		}
		onProgress("masscan", fmt.Sprintf("found %d host(s) with open ports", len(discovered)))
	}

	if len(excludes.IPPorts) > 0 {
		if removed := filterIPPortExcludes(discovered, excludes.IPPorts); removed > 0 {
			onProgress("discovery", fmt.Sprintf("ip+port excludes applied: removed %d result(s)", removed))
		}
	}

	if len(discovered) == 0 {
		return &ScanResult{TargetSpec: targetSpec, PortSpec: portSpec}, nil
	}

	var resultsMu sync.Mutex
	var results []HostResult
	tracker := newHostTracker(func(host HostResult) {
		resultsMu.Lock()
		results = append(results, host)
		resultsMu.Unlock()
		onHostComplete(host)
	})

	// These three worker pools start now and run for the whole duration of
	// the nmap stage below (not as separate phases afterward) - that's
	// what makes per-host streaming possible at all: a host whose ports
	// need no follow-up work completes (and can be reported) immediately
	// after its own nmap call, without waiting for every other host's
	// screenshots to finish first.
	shotJobs := make(chan shotJob, cfg.GowitnessConcurrency)
	rdpJobs := make(chan rdpJob, cfg.RDPConcurrency)
	tlsJobs := make(chan tlsJob, cfg.Concurrency)

	var subWG sync.WaitGroup
	startGowitnessWorkers(ctx, cfg, shotJobs, tracker, onProgress, &subWG)
	startRDPWorkers(ctx, cfg, rdpJobs, tracker, onProgress, &subWG)
	startTLSWorkers(ctx, cfg, tlsJobs, tracker, onProgress, &subWG)

	type nmapJob struct {
		ip    string
		ports []PortResult
	}
	nmapJobs := make(chan nmapJob, len(discovered))
	for ip, ports := range discovered {
		nmapJobs <- nmapJob{ip: ip, ports: ports}
	}
	close(nmapJobs)

	var nmapWG sync.WaitGroup
	var nmapOK, nmapFailed int
	var nmapCountMu sync.Mutex
	for i := 0; i < cfg.Concurrency; i++ {
		nmapWG.Add(1)
		go func() {
			defer nmapWG.Done()
			for j := range nmapJobs {
				onProgress("nmap", fmt.Sprintf("probing %s (%d port(s))", j.ip, len(j.ports)))
				host, err := RunNmap(ctx, cfg.NmapPath, j.ip, j.ports)
				if err != nil {
					onProgress("nmap", fmt.Sprintf("failed for %s: %v", j.ip, err))
					nmapCountMu.Lock()
					nmapFailed++
					nmapCountMu.Unlock()
					continue
				}
				nmapCountMu.Lock()
				nmapOK++
				nmapCountMu.Unlock()

				subTasks := 0
				for _, p := range host.Ports {
					if p.State != "open" {
						continue
					}
					if isHTTP, _ := isHTTPPort(p); isHTTP {
						subTasks++
					}
					if isRDPPort(p) {
						subTasks++
					}
					if isTLSPort(p) {
						subTasks++
					}
				}
				// Registered before any job is enqueued below, so the
				// tracker always knows the full expected count before a
				// worker could possibly report one sub-task done - see
				// hostTracker's own comment for why this ordering matters.
				tracker.register(host, subTasks)
				sniHostname := probeHostnames[host.IP] // "" if no override

				for _, p := range host.Ports {
					if p.State != "open" {
						continue
					}
					if isHTTP, useTLS := isHTTPPort(p); isHTTP {
						select {
						case shotJobs <- shotJob{ip: host.IP, port: p, useTLS: useTLS, sniHostname: sniHostname}:
						case <-ctx.Done():
							// register above already counted this sub-task
							// as expected - if it's never actually
							// enqueued, it must still be marked complete
							// (as a no-op) or this host's remaining count
							// would never reach zero and it would never be
							// reported at all.
							tracker.complete(host.IP, nil)
						}
					}
					if isRDPPort(p) {
						select {
						case rdpJobs <- rdpJob{ip: host.IP, port: p.Port}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}
					if isTLSPort(p) {
						select {
						case tlsJobs <- tlsJob{ip: host.IP, port: p.Port, sniHostname: sniHostname}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}
				}
			}
		}()
	}
	nmapWG.Wait()
	// Only the nmap workers ever enqueue onto these three channels, and
	// they've all finished now - safe to close so the sub-task worker
	// pools can drain and exit.
	close(shotJobs)
	close(rdpJobs)
	close(tlsJobs)
	subWG.Wait()

	if nmapOK == 0 && nmapFailed > 0 {
		return nil, fmt.Errorf("nmap stage: all %d host(s) failed", nmapFailed)
	}

	return &ScanResult{TargetSpec: targetSpec, PortSpec: portSpec, Hosts: results}, nil
}

// hostTracker tracks, per host, how many gowitness/RDP/TLS sub-tasks are
// still outstanding, and fires onComplete exactly once a host's count
// reaches zero. register must be called before any of that host's
// sub-tasks can possibly be reported done (RunScan above always registers
// before enqueueing that host's jobs), otherwise a fast-finishing
// sub-task could race ahead of registration.
type hostTracker struct {
	mu         sync.Mutex
	host       map[string]*HostResult
	remaining  map[string]int
	onComplete HostCompleteFunc
}

func newHostTracker(onComplete HostCompleteFunc) *hostTracker {
	return &hostTracker{
		host:       make(map[string]*HostResult),
		remaining:  make(map[string]int),
		onComplete: onComplete,
	}
}

func (t *hostTracker) register(host *HostResult, subTaskCount int) {
	if subTaskCount <= 0 {
		t.onComplete(*host)
		return
	}
	t.mu.Lock()
	t.host[host.IP] = host
	t.remaining[host.IP] = subTaskCount
	t.mu.Unlock()
}

// complete applies apply (nil if the sub-task failed - nothing to add)
// to the host's accumulated result, decrements its remaining count, and
// fires onComplete if that was the last outstanding sub-task.
func (t *hostTracker) complete(ip string, apply func(*HostResult)) {
	t.mu.Lock()
	host := t.host[ip]
	if apply != nil {
		apply(host)
	}
	t.remaining[ip]--
	done := t.remaining[ip] <= 0
	var result HostResult
	if done {
		result = *host
		delete(t.host, ip)
		delete(t.remaining, ip)
	}
	t.mu.Unlock()

	if done {
		t.onComplete(result)
	}
}

// retryDelay is a short pause before retrying a timed-out gowitness/RDP
// capture, giving a transient resource-contention spike (see
// GowitnessConcurrency's doc comment) a moment to subside rather than
// immediately retrying into the same contention.
const retryDelay = 2 * time.Second

// isTimeoutLikeErr reports whether err looks like it came from a capture
// that started but didn't finish in time, as opposed to a deterministic,
// guaranteed-to-fail-again error (e.g. RDP's NLA rejection, connection
// refused, binary not found) - retrying those would just waste time
// without ever succeeding. Both gowitness and xfreerdp report their own
// internal timeouts as plain error text rather than a typed Go error, so
// this is a pragmatic substring check rather than an errors.Is check.
func isTimeoutLikeErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline")
}

type shotJob struct {
	ip     string
	port   PortResult
	useTLS bool
	// sniHostname, when non-empty, is a manually-configured hostname
	// (hosts.probe_hostname) to navigate to instead of the bare ip - see
	// RunScan's doc comment. gowitness/Chrome has no IP-pinning +
	// hostname-override mechanism (checked via "gowitness scan single
	// --help" - no equivalent of Chrome's --host-resolver-rules is
	// exposed), so unlike the TLS probe below, this relies on the
	// hostname's own DNS still resolving to this ip - true for "my own
	// domain," which is the case this exists for.
	sniHostname string
}

// startGowitnessWorkers launches cfg.GowitnessConcurrency workers reading
// from jobs until it's closed, screenshotting each HTTP(S) port and
// reporting the result (or failure) to tracker. Runs for the whole
// duration of RunScan's nmap stage rather than as a separate phase
// afterward - see RunScan's doc comment.
func startGowitnessWorkers(ctx context.Context, cfg Config, jobs <-chan shotJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.GowitnessConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				scheme := "http"
				if j.useTLS {
					scheme = "https"
				}
				urlHost := j.ip
				if j.sniHostname != "" {
					urlHost = j.sniHostname
				}
				// net.JoinHostPort brackets an IPv6 literal ([::1]:8080)
				// and leaves an IPv4 one (or a plain hostname) alone - a
				// plain fmt.Sprintf("%s:%d", ip, port) produces an invalid
				// URL for IPv6 (e.g. "http://fe80::1:8080").
				url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(urlHost, strconv.Itoa(j.port.Port)))

				onProgress("gowitness", fmt.Sprintf("capturing %s", url))
				shot, err := RunGowitness(ctx, cfg, url, j.port.Port)
				if err != nil && isTimeoutLikeErr(err) {
					onProgress("gowitness", fmt.Sprintf("retrying %s after timeout: %v", url, err))
					select {
					case <-time.After(retryDelay):
					case <-ctx.Done():
					}
					shot, err = RunGowitness(ctx, cfg, url, j.port.Port)
				}
				if err != nil {
					onProgress("gowitness", fmt.Sprintf("failed for %s: %v", url, err))
					tracker.complete(j.ip, nil)
					continue
				}
				if text, err := RunOCR(ctx, cfg.TesseractPath, shot.ImagePath); err != nil {
					onProgress("gowitness", fmt.Sprintf("ocr failed for %s: %v", url, err))
				} else {
					shot.OCRText = text
				}
				tracker.complete(j.ip, func(h *HostResult) { h.Screenshots = append(h.Screenshots, *shot) })
			}
		}()
	}
}

type rdpJob struct {
	ip   string
	port int
}

// startRDPWorkers is startGowitnessWorkers' RDP equivalent - see its doc
// comment.
func startRDPWorkers(ctx context.Context, cfg Config, jobs <-chan rdpJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.RDPConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				target := net.JoinHostPort(j.ip, strconv.Itoa(j.port))

				onProgress("rdp", fmt.Sprintf("capturing %s", target))
				shot, err := RunRDPScreenshot(ctx, cfg, j.ip, j.port)
				if err != nil && isTimeoutLikeErr(err) {
					onProgress("rdp", fmt.Sprintf("retrying %s after timeout: %v", target, err))
					select {
					case <-time.After(retryDelay):
					case <-ctx.Done():
					}
					shot, err = RunRDPScreenshot(ctx, cfg, j.ip, j.port)
				}
				if err != nil {
					onProgress("rdp", fmt.Sprintf("failed for %s: %v", target, err))
					tracker.complete(j.ip, nil)
					continue
				}
				if text, err := RunOCR(ctx, cfg.TesseractPath, shot.ImagePath); err != nil {
					onProgress("rdp", fmt.Sprintf("ocr failed for %s: %v", target, err))
				} else {
					shot.OCRText = text
				}
				tracker.complete(j.ip, func(h *HostResult) { h.RDPScreenshots = append(h.RDPScreenshots, *shot) })
			}
		}()
	}
}

type tlsJob struct {
	ip   string
	port int
	// sniHostname, when non-empty, is a manually-configured hostname
	// (hosts.probe_hostname) sent as the TLS SNI value instead of the
	// bare ip - see RunScan's doc comment. Unlike gowitness, the dial
	// target itself always stays the exact ip regardless (RunTLSCertProbe
	// only uses this for the ServerName in its tls.Config), so there's no
	// DNS dependency here.
	sniHostname string
}

// startTLSWorkers is startGowitnessWorkers' TLS-certificate equivalent -
// see its doc comment. Uses cfg.Concurrency (like nmap) rather than its
// own dedicated setting, since a TLS handshake is much lighter than a
// gowitness/RDP screenshot capture (no external process/Chrome/Xvfb).
func startTLSWorkers(ctx context.Context, cfg Config, jobs <-chan tlsJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				target := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
				sni := j.ip
				if j.sniHostname != "" {
					sni = j.sniHostname
				}

				onProgress("tls", fmt.Sprintf("capturing %s", target))
				cert, err := RunTLSCertProbe(ctx, cfg, j.ip, j.port, sni)
				if err != nil {
					onProgress("tls", fmt.Sprintf("failed for %s: %v", target, err))
					tracker.complete(j.ip, nil)
					continue
				}
				tracker.complete(j.ip, func(h *HostResult) { h.TLSCertificates = append(h.TLSCertificates, *cert) })
			}
		}()
	}
}
