package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"porttorch/scanner/internal/api"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/logging"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/tui"
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
	var target, ports string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Runs a non-interactive scan and submits the result to the webserver",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required (IPv4 single IP/CIDR/range, or a single IPv6 address / comma-separated list of them)")
			}
			if ports == "" {
				return fmt.Errorf("--ports is required (e.g. 1-1000 or 22,80,443)")
			}
			return runScan(*configPath, target, ports)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Target: IPv4 single IP/CIDR/range (e.g. 192.168.1.0/24) or a single IPv6 address / comma-separated list (e.g. 2001:db8::1)")
	cmd.Flags().StringVar(&ports, "ports", "", "Port spec, e.g. 1-1000 or 22,80,443")
	return cmd
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
			return tui.Run(c, cfg.Pipeline())
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

			server := api.NewServer(c, cfg.Pipeline(), cfg.ControlAPIToken, log)

			pollInterval := time.Duration(cfg.PollIntervalSeconds) * time.Second
			go server.StartPolling(context.Background(), pollInterval)
			log.Info("polling for pending scan requests started", "event", "serve.polling_started", "poll_interval", pollInterval.String())

			// Separate loop from StartPolling above: that one blocks for
			// the whole duration of a queue-triggered scan, so it can't
			// also notice a cancellation request in the meantime.
			go server.StartCancelWatcher(context.Background(), pollInterval)
			log.Info("scan cancellation watcher started", "event", "serve.cancel_watcher_started", "poll_interval", pollInterval.String())

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

	result, scanErr := pipeline.RunScan(ctx, cfg.Pipeline(), target, ports, excludes, probeHostnames,
		func(stage, message string) {
			log.Info(message, "event", "scan.progress", "scan_job_id", jobID, "stage", stage)
		},
		func(host pipeline.HostResult) {
			defer pipeline.CleanupScreenshots([]pipeline.HostResult{host})

			submitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err := c.SubmitHostResult(submitCtx, jobID, host, func(kind string, port int, err error) {
				log.Warn(kind+" submission failed", "event", "scan."+kind+"_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "port", port, "error", err.Error())
			})
			if err != nil {
				log.Warn("host submission failed, skipping", "event", "scan.host_submit_failed", "scan_job_id", jobID, "target_ip", host.IP, "error", err.Error())
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
