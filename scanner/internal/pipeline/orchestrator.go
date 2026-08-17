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

	NucleiPath           string
	NucleiTimeoutSeconds int
	// NucleiConcurrency is deliberately separate from (and defaults much
	// lower than) Concurrency, for the same reason as
	// GowitnessConcurrency/RDPConcurrency - each nuclei invocation walks
	// its whole selected template set against one target, far heavier
	// than a single nmap process.
	NucleiConcurrency int
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
	if c.NucleiPath == "" {
		c.NucleiPath = "nuclei"
	}
	if c.NucleiTimeoutSeconds <= 0 {
		c.NucleiTimeoutSeconds = 10
	}
	if c.NucleiConcurrency <= 0 {
		c.NucleiConcurrency = 2
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
// point (nmap, gowitness, RDP, TLS, SNMP, IPMI, DNS recursion) already
// ran with per-host worker pools, so onHostComplete fires as soon as an
// individual host's own pipeline finishes rather than waiting for the
// slowest host in the batch - see hostTracker below for how completion
// is tracked across seven concurrently-running stages instead of seven
// sequential ones.
//
// probeHostnames (see client.Client.GetProbeHostnames) maps an IP to a
// manually-configured hostname to use instead of the bare IP for the TLS
// certificate probe's SNI and the gowitness screenshot URL - needed for
// targets that reject/misroute a bare-IP (no working SNI) connection, e.g.
// nginx-style virtual hosting. A nil map is safe: a missing entry just
// means "no override, use the IP" (today's unchanged behavior).
//
// nseScripts is the resolved scan-profile script list passed straight
// through to RunNmap (see that function's own doc comment) - nil/empty
// means "Default", today's unchanged behavior.
//
// nucleiProfile gates the nuclei web-vulnerability-scanning stage
// entirely: nil means nuclei never runs at all - the nucleiJobs worker
// pool isn't even started, reproducing exactly today's behavior for every
// caller that doesn't resolve a real profile (see resolveNucleiProfile in
// internal/api/server.go, the only caller that ever passes non-nil).

// isHostname reports whether targetSpec should be treated as a DNS name to
// resolve, rather than an IPv4 address/CIDR/"start-end" range masscan
// already understands natively. Nothing in this codebase validated that
// shape before this existed - masscan simply errored out on anything it
// couldn't parse itself - so this is deliberately conservative: false for
// anything that already looks like a valid IP/CIDR/range/comma-separated
// multi-target spec (masscan accepts comma-separated targets too, and a
// hostname can never contain a comma), true only for the remainder. A
// hostname can legitimately contain a hyphen (e.g. "web-01.internal"), so
// the range check must confirm *both* sides of a "-" split are themselves
// valid IPs before concluding it's a range - a plain "contains a hyphen"
// check would misclassify that example as a range.
func isHostname(targetSpec string) bool {
	targetSpec = strings.TrimSpace(targetSpec)
	if targetSpec == "" || strings.Contains(targetSpec, ",") {
		return false
	}
	if net.ParseIP(targetSpec) != nil {
		return false
	}
	if _, _, err := net.ParseCIDR(targetSpec); err == nil {
		return false
	}
	if before, after, ok := strings.Cut(targetSpec, "-"); ok {
		if net.ParseIP(strings.TrimSpace(before)) != nil && net.ParseIP(strings.TrimSpace(after)) != nil {
			return false
		}
	}
	return true
}

// resolveHostnameIPv4 resolves hostname via the scanner's own local DNS
// and returns the first IPv4 address found. IPv4 only for now - masscan
// (the discovery engine a resolved hostname target still goes through) has
// no IPv6 capability at all, matching the existing IPv6 target path's own
// single/list-address-only scoping (see parseIPv6TargetList) rather than
// folding hostname resolution into it too. Only the first address is used,
// not every A record - the least-surprising interpretation of "I typed a
// hostname, I meant that one host," and it avoids unintentionally sweeping
// every edge IP behind a load-balanced/CDN-fronted name.
func resolveHostnameIPv4(ctx context.Context, hostname string) (string, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no IPv4 address found for %s", hostname)
	}
	return addrs[0].String(), nil
}

// withProbeHostname returns a copy of probeHostnames with ip -> hostname
// added, rather than mutating the input in place - every current caller of
// RunScan builds/fetches probeHostnames fresh per call (server.go's
// runScan calls GetProbeHostnames() once per scan), but mutating a
// caller-owned map in place would be a surprising aliasing bug for any
// future caller that doesn't. A nil input is handled the same as an empty
// one, so a caller that never set up probe hostnames at all still works.
func withProbeHostname(probeHostnames map[string]string, ip, hostname string) map[string]string {
	merged := make(map[string]string, len(probeHostnames)+1)
	for k, v := range probeHostnames {
		merged[k] = v
	}
	merged[ip] = hostname
	return merged
}

func RunScan(ctx context.Context, cfg Config, targetSpec, portSpec string, excludes Excludes, probeHostnames map[string]string, nseScripts []string, nucleiProfile *NucleiProfile, onProgress ProgressFunc, onHostComplete HostCompleteFunc) (*ScanResult, error) {
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

	// A hostname target (e.g. the Ad-hoc Scans page's Target field, or a
	// Schedule pointed at one) is resolved here, scanner-side, rather than
	// by the webserver - only the scanner can correctly resolve an
	// internal-only/split-horizon name from its own network (see the root
	// CLAUDE.md's "Why two separate services" - the webserver has no
	// visibility into whatever DNS the scanner's own network actually
	// uses, and a public-DNS resolution attempted webserver-side could
	// silently resolve to the wrong thing, or nothing, for an internal
	// name). masscan/nmap downstream never see the original hostname -
	// only the resolved IP - so the hostname is preserved solely via the
	// probeHostnames override below, the exact same mechanism a manually
	// set hosts.probe_hostname already uses for TLS SNI and the gowitness
	// screenshot URL (see RunScan's own doc comment above).
	if isHostname(targetSpec) {
		resolvedIP, err := resolveHostnameIPv4(ctx, targetSpec)
		if err != nil {
			return nil, fmt.Errorf("resolving hostname %q: %w", targetSpec, err)
		}
		onProgress("discovery", fmt.Sprintf("resolved %s -> %s", targetSpec, resolvedIP))
		probeHostnames = withProbeHostname(probeHostnames, resolvedIP, targetSpec)
		targetSpec = resolvedIP
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
	snmpJobs := make(chan snmpJob, cfg.Concurrency)
	ipmiJobs := make(chan ipmiJob, cfg.Concurrency)
	dnsRecursionJobs := make(chan dnsRecursionJob, cfg.Concurrency)
	upnpJobs := make(chan upnpJob, cfg.Concurrency)
	// Only created/started when a nuclei profile is actually active - see
	// RunScan's doc comment. Left nil otherwise, never closed below, and
	// never enqueued onto in the per-port loop (all three guarded by the
	// same nucleiProfile != nil check).
	var nucleiJobs chan nucleiJob
	if nucleiProfile != nil {
		nucleiJobs = make(chan nucleiJob, cfg.NucleiConcurrency)
	}

	var subWG sync.WaitGroup
	startGowitnessWorkers(ctx, cfg, shotJobs, tracker, onProgress, &subWG)
	startRDPWorkers(ctx, cfg, rdpJobs, tracker, onProgress, &subWG)
	startTLSWorkers(ctx, cfg, tlsJobs, tracker, onProgress, &subWG)
	startSNMPWorkers(ctx, cfg, snmpJobs, tracker, onProgress, &subWG)
	startIPMIWorkers(ctx, cfg, ipmiJobs, tracker, onProgress, &subWG)
	startDNSRecursionWorkers(ctx, cfg, dnsRecursionJobs, tracker, onProgress, &subWG)
	startUPnPWorkers(ctx, cfg, upnpJobs, tracker, onProgress, &subWG)
	if nucleiProfile != nil {
		startNucleiWorkers(ctx, cfg, *nucleiProfile, nucleiJobs, tracker, onProgress, &subWG)
	}

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
				// Deliberately doesn't call tracker.complete on panic,
				// unlike every sub-task worker pool below - a panic here
				// can happen before tracker.register (e.g. inside RunNmap
				// itself), and calling complete for a host that was never
				// registered dereferences a nil *HostResult (a second
				// panic). The accepted tradeoff: a panic during this
				// specific host's processing means that host's result is
				// simply lost (or, if it panicked after registering but
				// before every sub-task was dispatched, its remaining
				// count never reaches zero and onHostComplete never fires
				// for it) - never ideal, but strictly better than the
				// panic taking down every other host and every other
				// in-progress scan in the same "serve" process with it.
				recoverJob(func(r any) {
					onProgress("nmap", fmt.Sprintf("panic recovered probing %s: %v", j.ip, r))
				}, func() {
					onProgress("nmap", fmt.Sprintf("probing %s (%d port(s))", j.ip, len(j.ports)))
					host, err := RunNmap(ctx, cfg.NmapPath, j.ip, j.ports, nseScripts)
					if err != nil {
						onProgress("nmap", fmt.Sprintf("failed for %s: %v", j.ip, err))
						nmapCountMu.Lock()
						nmapFailed++
						nmapCountMu.Unlock()
						return
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
							if nucleiProfile != nil {
								subTasks++
							}
						}
						if isRDPPort(p) {
							subTasks++
						}
						if isTLSPort(p) {
							subTasks++
						}
					}
					// SNMP, IPMI, DNS recursion, and UPnP are all unconditional
					// (every host, not gated on any already-discovered port -
					// see snmp.go's doc comment for why; ipmi.go's
					// RunIPMIProbe, dnsrecursion.go's RunDNSRecursionProbe, and
					// upnp.go's RunUPnPProbe are the identical exception for
					// UDP/623, UDP/53, and UDP/1900 respectively), except when
					// an exclude specifically covers that port for this host -
					// none of the TCP-only exclude mechanisms above would
					// otherwise ever see any of these four ports.
					probeSNMP := !isPortExcludedForHost(host.IP, 161, excludes)
					if probeSNMP {
						subTasks++
					}
					probeIPMI := !isPortExcludedForHost(host.IP, 623, excludes)
					if probeIPMI {
						subTasks++
					}
					probeDNSRecursion := !isPortExcludedForHost(host.IP, 53, excludes)
					if probeDNSRecursion {
						subTasks++
					}
					probeUPnP := !isPortExcludedForHost(host.IP, 1900, excludes)
					if probeUPnP {
						subTasks++
					}
					// Registered before any job is enqueued below, so the
					// tracker always knows the full expected count before a
					// worker could possibly report one sub-task done - see
					// hostTracker's own comment for why this ordering matters.
					tracker.register(host, subTasks)
					sniHostname := probeHostnames[host.IP] // "" if no override

					if probeSNMP {
						select {
						case snmpJobs <- snmpJob{ip: host.IP}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}
					if probeIPMI {
						select {
						case ipmiJobs <- ipmiJob{ip: host.IP}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}
					if probeDNSRecursion {
						select {
						case dnsRecursionJobs <- dnsRecursionJob{ip: host.IP}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}
					if probeUPnP {
						select {
						case upnpJobs <- upnpJob{ip: host.IP}:
						case <-ctx.Done():
							tracker.complete(host.IP, nil)
						}
					}

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
							if nucleiProfile != nil {
								select {
								case nucleiJobs <- nucleiJob{ip: host.IP, port: p, useTLS: useTLS, sniHostname: sniHostname}:
								case <-ctx.Done():
									tracker.complete(host.IP, nil)
								}
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
				})
			}
		}()
	}
	nmapWG.Wait()
	// Only the nmap workers ever enqueue onto these six channels, and
	// they've all finished now - safe to close so the sub-task worker
	// pools can drain and exit.
	close(shotJobs)
	close(rdpJobs)
	close(tlsJobs)
	close(snmpJobs)
	close(ipmiJobs)
	close(dnsRecursionJobs)
	close(upnpJobs)
	if nucleiJobs != nil {
		close(nucleiJobs)
	}
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

// recoverJob runs fn for one job, recovering from any panic instead of
// letting it crash the entire process - the pipeline processes a lot of
// unpredictable external-tool output (nmap/masscan XML, gowitness JSON,
// ...) across many concurrent goroutines, and in a long-running "serve"
// process a single malformed response from one host must never take down
// every other scan currently in progress (a plain, unrecovered panic in
// any goroutine terminates the whole Go process, not just that
// goroutine). onPanic is called with the recovered value so the caller
// can report it and do whatever bookkeeping that worker pool's other
// failure paths already do (see each start*Workers function).
func recoverJob(onPanic func(recovered any), fn func()) {
	defer func() {
		if r := recover(); r != nil {
			onPanic(r)
		}
	}()
	fn()
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
				recoverJob(func(r any) {
					onProgress("gowitness", fmt.Sprintf("panic recovered capturing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
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
						return
					}
					if text, err := RunOCR(ctx, cfg.TesseractPath, shot.ImagePath); err != nil {
						onProgress("gowitness", fmt.Sprintf("ocr failed for %s: %v", url, err))
					} else {
						shot.OCRText = text
					}
					tracker.complete(j.ip, func(h *HostResult) { h.Screenshots = append(h.Screenshots, *shot) })
				})
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
				recoverJob(func(r any) {
					onProgress("rdp", fmt.Sprintf("panic recovered capturing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
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
						return
					}
					if text, err := RunOCR(ctx, cfg.TesseractPath, shot.ImagePath); err != nil {
						onProgress("rdp", fmt.Sprintf("ocr failed for %s: %v", target, err))
					} else {
						shot.OCRText = text
					}
					tracker.complete(j.ip, func(h *HostResult) { h.RDPScreenshots = append(h.RDPScreenshots, *shot) })
				})
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
				recoverJob(func(r any) {
					onProgress("tls", fmt.Sprintf("panic recovered capturing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
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
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.TLSCertificates = append(h.TLSCertificates, *cert) })
				})
			}
		}()
	}
}

type snmpJob struct {
	ip string
}

// startSNMPWorkers is startGowitnessWorkers' SNMP-probe equivalent - see
// its doc comment. Uses cfg.Concurrency (like nmap/TLS) rather than its
// own dedicated setting; unlike gowitness/RDP, this shells out to a
// single small nmap invocation per host (see snmp.go), not a heavy
// external process. A nil result (RunSNMPProbe found nothing - the
// common case, since most hosts don't run SNMP at all) completes the
// sub-task without adding a port; a non-nil result is appended to the
// host's Ports the same way any other discovered port would be.
func startSNMPWorkers(ctx context.Context, cfg Config, jobs <-chan snmpJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				recoverJob(func(r any) {
					onProgress("snmp", fmt.Sprintf("panic recovered probing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
					onProgress("snmp", fmt.Sprintf("probing %s (udp/161)", j.ip))
					port, err := RunSNMPProbe(ctx, cfg.NmapPath, j.ip)
					if err != nil {
						onProgress("snmp", fmt.Sprintf("failed for %s: %v", j.ip, err))
						tracker.complete(j.ip, nil)
						return
					}
					if port == nil {
						tracker.complete(j.ip, nil)
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.Ports = append(h.Ports, *port) })
				})
			}
		}()
	}
}

type ipmiJob struct {
	ip string
}

// startIPMIWorkers is startSNMPWorkers' IPMI-probe equivalent - see its
// doc comment and ipmi.go's RunIPMIProbe. Same reasoning throughout:
// cfg.Concurrency, a nil result (the common case - most hosts don't run
// an IPMI/BMC interface) completes the sub-task without adding a port, a
// non-nil result is appended to the host's Ports like any other
// discovered port.
func startIPMIWorkers(ctx context.Context, cfg Config, jobs <-chan ipmiJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				recoverJob(func(r any) {
					onProgress("ipmi", fmt.Sprintf("panic recovered probing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
					onProgress("ipmi", fmt.Sprintf("probing %s (udp/623)", j.ip))
					port, err := RunIPMIProbe(ctx, cfg.NmapPath, j.ip)
					if err != nil {
						onProgress("ipmi", fmt.Sprintf("failed for %s: %v", j.ip, err))
						tracker.complete(j.ip, nil)
						return
					}
					if port == nil {
						tracker.complete(j.ip, nil)
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.Ports = append(h.Ports, *port) })
				})
			}
		}()
	}
}

type dnsRecursionJob struct {
	ip string
}

// startDNSRecursionWorkers is startSNMPWorkers'/startIPMIWorkers' DNS-
// recursion-probe equivalent - see its doc comment and dnsrecursion.go's
// RunDNSRecursionProbe. Same reasoning throughout: cfg.Concurrency, a nil
// result (the common case - most hosts don't run a DNS server, and a
// correctly-configured one won't be an open recursive resolver anyway)
// completes the sub-task without adding a port, a non-nil result is
// appended to the host's Ports like any other discovered port.
func startDNSRecursionWorkers(ctx context.Context, cfg Config, jobs <-chan dnsRecursionJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				recoverJob(func(r any) {
					onProgress("dnsrecursion", fmt.Sprintf("panic recovered probing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
					onProgress("dnsrecursion", fmt.Sprintf("probing %s (udp/53)", j.ip))
					port, err := RunDNSRecursionProbe(ctx, cfg.NmapPath, j.ip)
					if err != nil {
						onProgress("dnsrecursion", fmt.Sprintf("failed for %s: %v", j.ip, err))
						tracker.complete(j.ip, nil)
						return
					}
					if port == nil {
						tracker.complete(j.ip, nil)
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.Ports = append(h.Ports, *port) })
				})
			}
		}()
	}
}

type upnpJob struct {
	ip string
}

// startUPnPWorkers is startSNMPWorkers'/startIPMIWorkers'/
// startDNSRecursionWorkers' UPnP-probe equivalent - see its doc comment
// and upnp.go's RunUPnPProbe. Same reasoning throughout: cfg.Concurrency,
// a nil result (the common case - most hosts don't run a UPnP responder)
// completes the sub-task without adding a port, a non-nil result is
// appended to the host's Ports like any other discovered port.
func startUPnPWorkers(ctx context.Context, cfg Config, jobs <-chan upnpJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				recoverJob(func(r any) {
					onProgress("upnp", fmt.Sprintf("panic recovered probing %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
					onProgress("upnp", fmt.Sprintf("probing %s (udp/1900)", j.ip))
					port, err := RunUPnPProbe(ctx, cfg.NmapPath, j.ip)
					if err != nil {
						onProgress("upnp", fmt.Sprintf("failed for %s: %v", j.ip, err))
						tracker.complete(j.ip, nil)
						return
					}
					if port == nil {
						tracker.complete(j.ip, nil)
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.Ports = append(h.Ports, *port) })
				})
			}
		}()
	}
}

type nucleiJob struct {
	ip          string
	port        PortResult
	useTLS      bool
	sniHostname string
}

// startNucleiWorkers is startGowitnessWorkers' nuclei equivalent - same
// job shape (gated on isHTTPPort, reusing the same scheme/sniHostname URL
// construction), except a failure just means zero findings appended
// rather than the sub-task producing nothing at all. Uses
// cfg.NucleiConcurrency, separate from GowitnessConcurrency, for the same
// heavy-external-process reasoning as gowitness/RDP - nuclei walks its
// whole selected template set per target, not a single quick request.
func startNucleiWorkers(ctx context.Context, cfg Config, profile NucleiProfile, jobs <-chan nucleiJob, tracker *hostTracker, onProgress ProgressFunc, wg *sync.WaitGroup) {
	for i := 0; i < cfg.NucleiConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				recoverJob(func(r any) {
					onProgress("nuclei", fmt.Sprintf("panic recovered scanning %s: %v", j.ip, r))
					tracker.complete(j.ip, nil)
				}, func() {
					scheme := "http"
					if j.useTLS {
						scheme = "https"
					}
					urlHost := j.ip
					if j.sniHostname != "" {
						urlHost = j.sniHostname
					}
					url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(urlHost, strconv.Itoa(j.port.Port)))

					onProgress("nuclei", fmt.Sprintf("scanning %s", url))
					findings, err := RunNuclei(ctx, cfg, url, j.port.Port, profile)
					if err != nil {
						onProgress("nuclei", fmt.Sprintf("failed for %s: %v", url, err))
						tracker.complete(j.ip, nil)
						return
					}
					tracker.complete(j.ip, func(h *HostResult) { h.NucleiFindings = append(h.NucleiFindings, findings...) })
				})
			}
		}()
	}
}
