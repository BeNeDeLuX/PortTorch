package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newScanCmd(configPath *string) *cobra.Command {
	var target, ports, targetsFile string
	var dryRun bool

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
			if dryRun {
				return runDryRun(*configPath, target, ports)
			}
			return runScan(*configPath, target, ports)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Target: IPv4 single IP/CIDR/range (e.g. 192.168.1.0/24) or a single IPv6 address / comma-separated list (e.g. 2001:db8::1)")
	cmd.Flags().StringVar(&ports, "ports", "", "Port spec, e.g. 1-1000 or 22,80,443")
	cmd.Flags().StringVar(&targetsFile, "targets-file", "", "Path to a file with one target spec per line (IPv4 IP/CIDR/range, or a single IPv6 address - never mixed) - combined into one scan, exactly as if joined with commas and passed to --target. Blank lines and lines starting with # are ignored. Mutually exclusive with --target.")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would actually be scanned (effective targets/ports after excludes) without running masscan/nmap or creating a scan job")
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

			server := api.NewServer(c, cfg.Pipeline(), cfg.SubmitQueueDir, cfg.ControlAPIToken, auditLog, log)

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

			pollInterval := time.Duration(cfg.PollIntervalSeconds) * time.Second
			go server.StartPolling(context.Background(), pollInterval)
			log.Info("polling for pending scan requests started", "event", "serve.polling_started", "poll_interval", pollInterval.String())

			// Separate loop from StartPolling above: that one blocks for
			// the whole duration of a queue-triggered scan, so it can't
			// also notice a cancellation request in the meantime.
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

func runScan(configPath, target, ports string) error {
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

	// nil nseScripts/nucleiProfile: the one-shot scan CLI has no scan-
	// profile concept - always runs DefaultNSEScripts and never runs
	// nuclei, same as before nuclei existed.
	result, scanErr := pipeline.RunScan(ctx, cfg.Pipeline(), target, ports, excludes, probeHostnames, nil, nil,
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
func runDryRun(configPath, target, ports string) error {
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
	printPreview(preview)
	return nil
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
