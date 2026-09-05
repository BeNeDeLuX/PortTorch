package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"porttorch/scanner/internal/api"
	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/logging"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/progress"
	"porttorch/scanner/internal/submitqueue"
	"porttorch/scanner/internal/tui"
	"porttorch/scanner/internal/updater"
	"porttorch/scanner/internal/version"
)

func defaultConfigPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "porttorch", "config.yaml")
	}
	return "config.yaml"
}

func main() {
	var configPath string

	root := &cobra.Command{
		Use:     "porttorch",
		Short:   "PortTorch: internal network scanner (masscan -> nmap -> gowitness)",
		Version: version.Version,
		// main() below already prints the returned error - without this,
		// cobra's own default error handling would print it a second
		// time before main() ever runs.
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath(), "Path to the config file")

	root.AddCommand(newScanCmd(&configPath))
	root.AddCommand(newMenuCmd(&configPath))
	root.AddCommand(newServeCmd(&configPath))
	root.AddCommand(newDoctorCmd(&configPath))
	root.AddCommand(newQueueCmd(&configPath))
	root.AddCommand(newHistoryCmd(&configPath))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// scanOptions are the per-scan choices the dashboard has always offered
// and the CLI never did. Until these flags existed, a scan run directly
// on a scanner host silently differed from the same scan queued from the
// dashboard: always the 31 default NSE scripts, never nuclei, always the
// configured masscan rate. That difference was invisible - the scan
// simply found less.
type scanOptions struct {
	nseProfile  string
	nseScripts  string
	nuclei      string
	nucleiTags  string
	masscanRate int
}

// resolve turns the typed flags into what RunScan takes, rejecting an
// unknown profile name rather than silently falling back to the default -
// a typo'd --nse-profile that quietly ran the default set would be the
// same class of silent difference these flags exist to remove.
func (o scanOptions) resolve() (nse []string, nuclei *pipeline.NucleiProfile, rate *int, err error) {
	switch o.nseProfile {
	case "", "default":
		nse = nil
	case "all-safe":
		nse = pipeline.ResolveNSEScripts("all_safe", nil)
	case "custom":
		if strings.TrimSpace(o.nseScripts) == "" {
			return nil, nil, nil, fmt.Errorf("--nse-profile custom needs --nse-scripts with a comma-separated script list")
		}
		nse = pipeline.ResolveNSEScripts("custom", splitCommaList(o.nseScripts))
	default:
		return nil, nil, nil, fmt.Errorf("unknown --nse-profile %q (default, all-safe, custom)", o.nseProfile)
	}

	switch o.nuclei {
	case "", "off":
		nuclei = nil
	case "safe":
		nuclei = pipeline.ResolveNucleiProfile("safe", nil)
	case "custom":
		if strings.TrimSpace(o.nucleiTags) == "" {
			return nil, nil, nil, fmt.Errorf("--nuclei custom needs --nuclei-tags with a comma-separated tag list")
		}
		nuclei = pipeline.ResolveNucleiProfile("custom", splitCommaList(o.nucleiTags))
	default:
		return nil, nil, nil, fmt.Errorf("unknown --nuclei %q (off, safe, custom)", o.nuclei)
	}

	if o.masscanRate > 0 {
		r := o.masscanRate
		rate = &r
	}
	return nse, nuclei, rate, nil
}

func splitCommaList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func newScanCmd(configPath *string) *cobra.Command {
	var target, ports, targetsFile string
	var dryRun bool
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Runs a non-interactive scan and submits the result to the webserver",
		// A dry-run's own findings (e.g. "every requested port is
		// excluded") are a report, not a misused flag - showing the
		// usage block for that would be noise, same reasoning as
		// doctor's own SilenceUsage.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if target != "" && targetsFile != "" {
				return fmt.Errorf("--target and --targets-file are mutually exclusive")
			}
			if targetsFile != "" {
				combined, err := parseTargetsFile(targetsFile)
				if err != nil {
					return err
				}
				target = combined
			}
			if target == "" {
				return fmt.Errorf("--target or --targets-file is required (IPv4 single IP/CIDR/range, or a single IPv6 address / comma-separated list of them)")
			}
			if ports == "" {
				return fmt.Errorf("--ports is required (e.g. 1-1000 or 22,80,443)")
			}
			nse, nuclei, rate, err := opts.resolve()
			if err != nil {
				return err
			}
			if dryRun {
				return runDryRun(*configPath, target, ports, opts, nse, nuclei, rate)
			}
			return runScan(*configPath, target, ports, nse, nuclei, rate)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Target: IPv4 single IP/CIDR/range (e.g. 192.168.1.0/24) or a single IPv6 address / comma-separated list (e.g. 2001:db8::1)")
	cmd.Flags().StringVar(&ports, "ports", "", "Port spec, e.g. 1-1000 or 22,80,443")
	cmd.Flags().StringVar(&targetsFile, "targets-file", "", "Path to a file with one target spec per line (IPv4 IP/CIDR/range, or a single IPv6 address - never mixed) - combined into one scan, exactly as if joined with commas and passed to --target. Blank lines and lines starting with # are ignored. Mutually exclusive with --target.")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would actually be scanned - address and port counts, an estimated masscan runtime, the NSE/nuclei selection and every exclude that applies - without running masscan/nmap or creating a scan job")
	cmd.Flags().StringVar(&opts.nseProfile, "nse-profile", "default", "Which NSE scripts nmap runs: default (31 curated scripts), all-safe (nmap's own safe-and-not-intrusive category, unioned with default), or custom (needs --nse-scripts)")
	cmd.Flags().StringVar(&opts.nseScripts, "nse-scripts", "", "Comma-separated NSE script names, for --nse-profile custom")
	cmd.Flags().StringVar(&opts.nuclei, "nuclei", "off", "Whether nuclei runs against discovered HTTP(S) ports: off, safe (excludes nuclei's dos/fuzz/intrusive tags), or custom (needs --nuclei-tags)")
	cmd.Flags().StringVar(&opts.nucleiTags, "nuclei-tags", "", "Comma-separated nuclei template tags, for --nuclei custom. Unlike NSE scripts these are not validated - an unknown tag matches no templates, which is a harmless no-op")
	cmd.Flags().IntVar(&opts.masscanRate, "rate", 0, "Override masscan's packets-per-second for this scan only. 0 uses masscanRate from config.yaml. Lower it for a fragile segment")
	return cmd
}

// parseTargetsFile reads target-spec fragments from path, one per line -
// blank lines and lines starting with "#" are skipped, a plain comment
// convention matching this project's own config.yaml style. Joins them
// with "," into exactly the same combined-target-list string --target
// would already accept directly: masscan's own target-spec grammar
// natively accepts a single positional argument that's itself a
// comma-separated list of IPs/CIDRs/ranges (confirmed against a real
// masscan run), and parseIPv6TargetList already accepts a comma-separated
// list of bare addresses (see its own doc comment) - so this needs no
// changes anywhere in the pipeline package, it just builds the exact
// string a user would otherwise have typed by hand.
func parseTargetsFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading targets file %s: %w", path, err)
	}
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("targets file %s contains no targets (blank lines and lines starting with # are ignored)", path)
	}
	return strings.Join(targets, ","), nil
}

func newMenuCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "menu",
		Short: "Interactive TUI menu for scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			c, err := client.New(cfg)
			if err != nil {
				return fmt.Errorf("building api client: %w", err)
			}
			// Opened once for the whole interactive session (the menu can
			// run several scans in a row without exiting) rather than
			// per-scan - see internal/auditlog's doc comment. Printed
			// here, before the TUI takes over the screen, since this
			// package has no stdout logging of its own once running (see
			// internal/logging's doc comment on why); a failure here is
			// never fatal, auditLog just stays nil.
			auditLog, err := auditlog.Open(cfg.ScanAuditLogPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not open scan audit log at %s, continuing without it: %v\n", cfg.ScanAuditLogPath, err)
			}
			defer auditLog.Close()
			return tui.Run(c, cfg.Pipeline(), cfg.SubmitQueueDir, auditLog)
		},
	}
}

func newServeCmd(configPath *string) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Starts the scanner's REST API to trigger scans remotely",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			c, err := client.New(cfg)
			if err != nil {
				return fmt.Errorf("building api client: %w", err)
			}

			listenAddr := cfg.ListenAddr
			if addr != "" {
				listenAddr = addr
			}

			log := logging.New()
			if cfg.ControlAPIToken == "" {
				log.Warn("controlApiToken is not set, the scanner API is reachable without authentication", "event", "serve.no_auth_token")
			}

			// Shared across every scan this process ever runs (unlike
			// "scan"/"menu", which each open their own for a single
			// scan) - see internal/auditlog's doc comment. A failure to
			// open it is logged but never fatal to serving; auditLog
			// stays nil and Write/Close on it are safe no-ops.
			auditLog, err := auditlog.Open(cfg.ScanAuditLogPath)
			if err != nil {
				log.Warn("could not open scan audit log, continuing without it", "event", "auditlog.open_failed", "path", cfg.ScanAuditLogPath, "error", err.Error())
			}

			server := api.NewServer(c, cfg.Pipeline(), cfg.MaxConcurrentScans, cfg.SubmitQueueDir, cfg.ControlAPIToken, auditLog, log)

			// Flushes any backlog left behind by a prior run before this
			// process starts serving - the periodic StartRetryWatcher
			// below only fires after its own first interval elapses, so
			// this synchronous drain avoids a startup gap where a backlog
			// would otherwise just sit there until then.
			drained := submitqueue.Drain(context.Background(), cfg.SubmitQueueDir, c)
			c.SetSubmitQueuePending(drained.Pending)
			if !drained.Empty() {
				log.Info("submit queue drained", "event", "submitqueue.drained", "succeeded", drained.Succeeded, "gave_up", drained.GaveUp, "pending", drained.Pending, "dropped", drained.Dropped, "rejected", drained.Rejected)
			}

			// Reported from the very first request, so an idle scanner
			// shows its capacity on the dashboard rather than "unknown"
			// until it happens to run something.
			server.PublishScanSlots()

			pollInterval := time.Duration(cfg.PollIntervalSeconds) * time.Second
			go server.StartPolling(context.Background(), pollInterval)
			log.Info("polling for pending scan requests started", "event", "serve.polling_started", "poll_interval", pollInterval.String(), "max_concurrent_scans", cfg.MaxConcurrentScans)

			// Separate loop from StartPolling above so that a cancellation
			// is noticed on its own fixed interval regardless of what the
			// queue loop is doing.
			go server.StartCancelWatcher(context.Background(), pollInterval)
			log.Info("scan cancellation watcher started", "event", "serve.cancel_watcher_started", "poll_interval", pollInterval.String())

			// Only "serve" mode has any persistent polling loop at all, so
			// self-update - like cancellation - only ever applies here,
			// never to the one-shot "scan"/"menu" processes.
			go updater.StartUpdateWatcher(context.Background(), c, server, pollInterval, log)
			log.Info("scanner update watcher started", "event", "serve.update_watcher_started", "poll_interval", pollInterval.String())

			// Its own watcher rather than another branch inside the one
			// above: a template refresh and a binary self-update are
			// independent actions that can both be outstanding at once,
			// and neither should have to wait on the other's outcome.
			go updater.StartTemplateUpdateWatcher(context.Background(), c, server, pollInterval, cfg.NucleiPath, log)
			log.Info("nuclei template update watcher started", "event", "serve.template_update_watcher_started", "poll_interval", pollInterval.String())

			// Dashboard-managed tuning (masscan rate, concurrency,
			// timeouts). Applied in memory only - config.yaml on disk is
			// never rewritten, so a restart falls back to the file and the
			// override is simply fetched again.
			go server.StartConfigWatcher(context.Background(), pollInterval)
			log.Info("scanner config watcher started", "event", "serve.config_watcher_started", "poll_interval", pollInterval.String())

			retryInterval := time.Duration(cfg.RetryIntervalSeconds) * time.Second
			go server.StartRetryWatcher(context.Background(), retryInterval)
			log.Info("submit retry watcher started", "event", "serve.retry_watcher_started", "retry_interval", retryInterval.String())

			log.Info("scanner api started", "event", "serve.started", "listen_addr", listenAddr)
			return server.Start(listenAddr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "Overrides listenAddr from the config, e.g. :9090")
	return cmd
}

func runScan(configPath, target, ports string, nseScripts []string, nucleiProfile *pipeline.NucleiProfile, masscanRate *int) error {
	log := logging.New()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	c, err := client.New(cfg)
	if err != nil {
		return fmt.Errorf("building api client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Opportunistically flushes any backlog left behind by a prior run's
	// submission failures (e.g. the webserver was briefly unreachable)
	// before this run's own scan even starts - see internal/submitqueue's
	// doc comment. A one-shot process like this has no ongoing loop to
	// retry from later, so "once, at startup" is the only chance it gets.
	drained := submitqueue.Drain(ctx, cfg.SubmitQueueDir, c)
	c.SetSubmitQueuePending(drained.Pending)
	if !drained.Empty() {
		log.Info("submit queue drained", "event", "submitqueue.drained", "succeeded", drained.Succeeded, "gave_up", drained.GaveUp, "pending", drained.Pending, "dropped", drained.Dropped, "rejected", drained.Rejected)
	}

	// A permanent local record of every host found, independent of the
	// webserver - see internal/auditlog's doc comment. A failure to open
	// it is logged but never fatal to the scan itself (auditLog stays
	// nil, and AuditLog.Write on a nil receiver is a safe no-op).
	auditLog, err := auditlog.Open(cfg.ScanAuditLogPath)
	if err != nil {
		log.Warn("could not open scan audit log, continuing without it", "event", "auditlog.open_failed", "path", cfg.ScanAuditLogPath, "error", err.Error())
	}
	defer auditLog.Close()

	// Fetched fresh (not cached) so the webserver's most current exclude
	// list is always honored; fetch failure aborts the scan rather than
	// proceeding unfiltered, since excludes exist to guarantee certain
	// targets are never scanned.
	excludes, err := c.GetExcludes(ctx)
	if err != nil {
		return fmt.Errorf("fetching excludes: %w", err)
	}
	// Same fetch-fresh, fail-closed treatment as excludes above - a manual
	// probe-hostname override only helps if it's actually applied.
	probeHostnames, err := c.GetProbeHostnames(ctx)
	if err != nil {
		return fmt.Errorf("fetching probe hostnames: %w", err)
	}

	start := time.Now()
	// Not cancellable: this is a one-shot process with nothing polling
	// during the blocking scan below, so a stop request could never reach
	// it (see CreateScanJob's doc comment).
	jobID, err := c.CreateScanJob(ctx, target, ports, false)
	if err != nil {
		return fmt.Errorf("creating scan job: %w", err)
	}
	log.Info("scan started", "event", "scan.started", "scan_job_id", jobID, "target", target, "ports", ports)

	// Pushes stage/log snapshots to the webserver every few seconds while
	// the scan runs, independent of and in addition to the local slog line
	// below - see internal/progress's doc comment for why this can't be
	// the other way around (webserver polling the scanner).
	tracker := progress.NewTracker(c, jobID, progress.DefaultPushInterval)
	defer tracker.Close()

	// Each host is submitted as soon as its own nmap+gowitness/RDP/TLS
	// work finishes, rather than batching the whole target range into one
	// submission after the entire scan completes - see pipeline.RunScan's
	// doc comment on why per-host, not per-port, is the achievable
	// granularity (masscan itself can't stream). A host whose submission
	// fails is logged and skipped (matches the existing tolerance for
	// individual screenshot/RDP/TLS submission failures below) rather than
	// aborting the rest of the scan.
	var tallyMu sync.Mutex
	var hostsSubmitted, openPorts, screenshots, rdpScreenshots, tlsCertificates int

	// nseScripts/nucleiProfile come from the flags (nil for the defaults,
	// which is what every invocation without them produces - byte
	// identical to before the flags existed). masscanRate overrides the
	// config on a copy, never on cfg itself, so a deliberately slow
	// one-off cannot leak into anything else.
	pcfg := cfg.Pipeline()
	if masscanRate != nil {
		pcfg.MasscanRate = *masscanRate
	}
	result, scanErr := pipeline.RunScan(ctx, pcfg, target, ports, excludes, probeHostnames, nseScripts, nucleiProfile,
		func(stage, message string) {
			log.Info(message, "event", "scan.progress", "scan_job_id", jobID, "stage", stage)
			tracker.Progress(stage, message)
		},
		func(host pipeline.HostResult) {
			defer pipeline.CleanupScreenshots([]pipeline.HostResult{host})

			submitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err := c.SubmitHostResult(submitCtx, jobID, host, func(kind string, port int, err error) {
				log.Warn(kind+" submission failed", "event", "scan."+kind+"_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "port", port, "error", err.Error())
				tracker.Progress(kind, fmt.Sprintf("submission for %s failed: %v", host.IP, err))
			})
			if err != nil {
				if submitqueue.IsPermanentFailure(err) {
					// The webserver definitively rejected this exact
					// payload (a 4xx) - retrying it unchanged would never
					// succeed, so it's not worth queuing at all.
					log.Error("host submission rejected by webserver, not queuing for retry", "event", "scan.host_submit_rejected", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
					tracker.Progress("submit", fmt.Sprintf("host submission for %s was rejected (not retried): %v", host.IP, err))
				} else {
					log.Warn("host submission failed, queuing for retry", "event", "scan.host_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
					tracker.Progress("submit", fmt.Sprintf("host submission for %s failed, queued for retry: %v", host.IP, err))
					if queueErr := submitqueue.Enqueue(cfg.SubmitQueueDir, jobID, host); queueErr != nil {
						log.Error("queuing failed host submission for retry also failed, result lost", "event", "submitqueue.enqueue_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", queueErr.Error())
					} else {
						c.SetSubmitQueuePending(submitqueue.CountPending(cfg.SubmitQueueDir))
					}
				}
				if writeErr := auditLog.Write(auditlog.EntryFromHost(jobID, host, false)); writeErr != nil {
					log.Warn("writing scan audit log entry failed", "event", "auditlog.write_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", writeErr.Error())
				}
				return
			}

			tallyMu.Lock()
			hostsSubmitted++
			openPorts += len(host.Ports)
			screenshots += len(host.Screenshots)
			rdpScreenshots += len(host.RDPScreenshots)
			tlsCertificates += len(host.TLSCertificates)
			tallyMu.Unlock()

			log.Info("host submitted", "event", "scan.host_submitted", "scan_job_id", jobID, "target_ip", host.IP, "open_ports", len(host.Ports))
			tracker.Progress("submit", fmt.Sprintf("submitted %s (%d open port(s))", host.IP, len(host.Ports)))
			if writeErr := auditLog.Write(auditlog.EntryFromHost(jobID, host, true)); writeErr != nil {
				log.Warn("writing scan audit log entry failed", "event", "auditlog.write_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", writeErr.Error())
			}
		},
	)

	if scanErr != nil {
		_ = c.CompleteScanJob(context.Background(), jobID, "failed")
		log.Error("scan failed", "event", "scan.failed", "scan_job_id", jobID, "error", scanErr.Error(), "duration_ms", time.Since(start).Milliseconds())
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if err := c.CompleteScanJob(context.Background(), jobID, "completed"); err != nil {
		return fmt.Errorf("completing scan job: %w", err)
	}

	log.Info("scan completed",
		"event", "scan.completed",
		"scan_job_id", jobID,
		"target", target,
		"ports", ports,
		"hosts_found", len(result.Hosts),
		"hosts_submitted", hostsSubmitted,
		"open_ports_found", openPorts,
		"screenshots", screenshots,
		"rdp_screenshots", rdpScreenshots,
		"tls_certificates", tlsCertificates,
		"duration_ms", time.Since(start).Milliseconds(),
	)
	return nil
}

// runDryRun fetches the same excludes a real scan would (the one
// unavoidable webserver round trip - excludes are fetched fresh, not
// cached, precisely because a stale copy could make a dry run lie about
// what would actually be scanned) and prints pipeline.PreviewScan's
// result as a human-readable report to stdout, same style as doctor's
// own plain-text checklist - not the JSON slog lines the rest of "scan"
// uses, since this is meant to be read directly by whoever typed the
// command, not shipped to a log aggregator. Never creates a scan job or
// touches masscan/nmap.
func runDryRun(configPath, target, ports string, opts scanOptions, nseScripts []string, nucleiProfile *pipeline.NucleiProfile, masscanRate *int) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	c, err := client.New(cfg)
	if err != nil {
		return fmt.Errorf("building api client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	excludes, err := c.GetExcludes(ctx)
	if err != nil {
		return fmt.Errorf("fetching excludes: %w", err)
	}

	preview, err := pipeline.PreviewScan(target, ports, excludes)
	if err != nil {
		return err
	}
	rate := cfg.MasscanRate
	if masscanRate != nil {
		rate = *masscanRate
	}
	printPreview(preview)
	printScanPlan(preview, opts, nseScripts, nucleiProfile, rate, masscanRate != nil)
	return nil
}

// printScanPlan is the half of a dry run that answers "should I actually
// start this?" - the excludes above answer "what gets left out", which is
// a different question and was previously the only one --dry-run could
// answer at all. The size and the runtime estimate are the point: a /16
// across every port is a decision worth making deliberately, and the
// number that makes it obvious was not on screen anywhere.
func printScanPlan(p *pipeline.PreviewResult, opts scanOptions, nseScripts []string, nuclei *pipeline.NucleiProfile, rate int, rateOverridden bool) {
	fmt.Println("\nScan plan:")

	addresses := p.AddressCount
	portCount := pipeline.CountPorts(p.EffectivePortSpec)
	if addresses > 0 {
		fmt.Printf("  Addresses:  %s\n", formatCount(addresses))
	} else {
		fmt.Println("  Addresses:  unknown (target form can't be counted without resolving it)")
	}
	fmt.Printf("  Ports:      %s per address\n", formatCount(int64(portCount)))

	if addresses > 0 && portCount > 0 {
		probes := addresses * int64(portCount)
		fmt.Printf("  Probes:     %s at %s packets/second\n", formatCount(probes), formatCount(int64(rate)))
		// masscan's own pass only - the nmap/screenshot/nuclei stages
		// that follow depend entirely on how much is actually found, so
		// estimating them would be a guess dressed up as a number.
		fmt.Printf("  masscan:    about %s (its pass only - nmap and the rest depend on what is found)\n",
			formatDuration(float64(probes)/float64(rate)))
	}

	if rateOverridden {
		fmt.Printf("  Rate:       %d packets/second (--rate, overriding config.yaml)\n", rate)
	}

	switch {
	case nseScripts == nil:
		fmt.Printf("  NSE:        default (%d curated scripts)\n", len(pipeline.DefaultNSEScripts))
	case opts.nseProfile == "all-safe":
		fmt.Printf("  NSE:        all-safe (%d scripts)\n", len(nseScripts))
	default:
		fmt.Printf("  NSE:        custom (%d scripts: %s)\n", len(nseScripts), strings.Join(nseScripts, ", "))
	}

	switch {
	case nuclei == nil:
		fmt.Println("  nuclei:     off")
	case len(nuclei.ExcludeTags) > 0:
		fmt.Printf("  nuclei:     safe (excluding tags: %s)\n", strings.Join(nuclei.ExcludeTags, ", "))
	default:
		fmt.Printf("  nuclei:     custom (tags: %s)\n", strings.Join(nuclei.Tags, ", "))
	}
}

// Thousands separators, because the numbers this prints are the whole
// reason for printing them and 4294967296 is not a number anyone reads.
func formatCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func formatDuration(seconds float64) string {
	switch {
	case seconds < 90:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 5400:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 172800:
		return fmt.Sprintf("%.1f hours", seconds/3600)
	default:
		return fmt.Sprintf("%.1f days", seconds/86400)
	}
}

func printPreview(p *pipeline.PreviewResult) {
	fmt.Printf("Target: %s\n", p.TargetSpec)
	fmt.Printf("Ports:  %s\n", p.PortSpec)
	if p.EffectivePortSpec == p.PortSpec {
		fmt.Println("Effective ports after excludes: unchanged (no port excludes apply)")
	} else if p.EffectivePortSpec == "" {
		fmt.Println("Effective ports after excludes: NONE - every requested port is excluded, this scan would find nothing")
	} else {
		fmt.Printf("Effective ports after excludes: %s\n", p.EffectivePortSpec)
	}

	if p.IsIPv6 {
		fmt.Printf("\nIPv6 targets (%d):\n", len(p.IPv6Targets))
		for _, t := range p.IPv6Targets {
			if t.Excluded {
				fmt.Printf("  [excluded] %s  (matches %s)\n", t.IP, t.Reason)
			} else {
				fmt.Printf("  [scanned]  %s\n", t.IP)
			}
		}
	} else {
		if p.SingleIPv4Target != nil {
			fmt.Println()
			if p.SingleIPv4Target.Excluded {
				fmt.Printf("Target %s is EXCLUDED (matches %s) - this scan would find nothing\n", p.SingleIPv4Target.IP, p.SingleIPv4Target.Reason)
			} else {
				fmt.Printf("Target %s would be scanned\n", p.SingleIPv4Target.IP)
			}
		}
		if len(p.AppliedIPExcludes) > 0 {
			fmt.Println("\nIP/CIDR/range excludes masscan would apply (--excludefile):")
			for _, ex := range p.AppliedIPExcludes {
				fmt.Printf("  %s\n", ex)
			}
		} else if p.SingleIPv4Target == nil {
			fmt.Println("\nNo IP/CIDR/range excludes apply.")
		}
	}

	if len(p.IPPortExcludes) > 0 {
		fmt.Println("\nip:port excludes (applied to results after discovery, can't be resolved to specific hosts yet):")
		for _, ex := range p.IPPortExcludes {
			fmt.Printf("  %s\n", ex)
		}
	}
}
