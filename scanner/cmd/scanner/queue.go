package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"porttorch/scanner/internal/auditlog"
	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/submitqueue"
)

// The local submit queue holds host results that could not be sent to the
// webserver - the durable half of "a scan's findings are not lost when
// the webserver is briefly unreachable". The dashboard shows the depth of
// it as one number per scanner, which is enough to notice a problem and
// not enough to do anything about it. These subcommands are for the case
// you are actually in when it matters: sitting on the scanner host,
// possibly because the webserver is the thing that is broken.
func newQueueCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "queue",
		Short: "Inspects and drains the local queue of scan results waiting to reach the webserver",
	}
	cmd.AddCommand(newQueueListCmd(configPath), newQueueFlushCmd(configPath), newQueueDiscardCmd(configPath))
	return cmd
}

func newQueueListCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:          "list",
		Short:        "Shows what is waiting to be submitted, oldest first",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			entries := submitqueue.ListPending(cfg.SubmitQueueDir)
			if len(entries) == 0 {
				fmt.Println("Submit queue is empty - every scan result has reached the webserver.")
				return nil
			}
			fmt.Printf("%d result(s) waiting in %s\n\n", len(entries), cfg.SubmitQueueDir)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "QUEUED\tHOST\tOPEN PORTS\tATTEMPTS\tSCAN JOB")
			for _, e := range entries {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n",
					e.QueuedAt.Format("2006-01-02 15:04"), e.IP, e.Ports, e.Attempts, e.JobID)
			}
			w.Flush()
			fmt.Println("\nRun 'porttorch queue flush' to retry them now.")
			return nil
		},
	}
}

func newQueueFlushCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "flush",
		Short: "Retries every queued result now, instead of waiting for the next scan or retry tick",
		Long: "Runs exactly the drain the scanner already performs at the start of every scan and periodically in serve mode - " +
			"the same attempt counting and the same give-up rules, just on demand.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			c, err := client.New(cfg)
			if err != nil {
				return fmt.Errorf("building api client: %w", err)
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			before := submitqueue.CountPending(cfg.SubmitQueueDir)
			if before == 0 {
				fmt.Println("Submit queue is empty - nothing to flush.")
				return nil
			}
			fmt.Printf("Flushing %d queued result(s)...\n", before)
			result := submitqueue.Drain(ctx, cfg.SubmitQueueDir, c)
			fmt.Printf("Submitted %d, still pending %d", result.Succeeded, result.Pending)
			if result.GaveUp > 0 {
				fmt.Printf(", gave up on %d (too old or too many attempts)", result.GaveUp)
			}
			if result.Rejected > 0 {
				fmt.Printf(", rejected %d (the webserver refused them - retrying unchanged would never succeed)", result.Rejected)
			}
			fmt.Println(".")
			if result.Pending > 0 {
				fmt.Println("Still pending usually means the webserver is unreachable - 'porttorch doctor' checks that.")
			}
			return nil
		},
	}
}

func newQueueDiscardCmd(configPath *string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "discard",
		Short: "Permanently deletes every queued result without submitting it",
		Long: "For a queue that can never drain - results belonging to a scan job the webserver no longer has, or a backlog " +
			"you have decided to abandon. The findings are lost; the scans themselves are already recorded in the local scan " +
			"audit log ('porttorch history').",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			pending := submitqueue.CountPending(cfg.SubmitQueueDir)
			if pending == 0 {
				fmt.Println("Submit queue is empty - nothing to discard.")
				return nil
			}
			// Destructive and unrecoverable, so it asks unless told not
			// to - the same shape as the dashboard's own confirmations.
			if !yes {
				fmt.Printf("Permanently delete %d queued scan result(s) without submitting them? Type 'yes' to confirm: ", pending)
				var answer string
				fmt.Scanln(&answer)
				if answer != "yes" {
					fmt.Println("Cancelled - nothing was deleted.")
					return nil
				}
			}
			removed, err := submitqueue.DiscardPending(cfg.SubmitQueueDir)
			if err != nil {
				return fmt.Errorf("discarding queue (removed %d before failing): %w", removed, err)
			}
			fmt.Printf("Discarded %d queued result(s).\n", removed)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the confirmation prompt")
	return cmd
}

// Kept next to the queue command because they answer two halves of the
// same question - what this scanner found, and what of it actually
// arrived. The audit log records every host either way, with a submitted
// flag, so "--unsubmitted" is the durable record of what the webserver
// never got, including entries the queue has since given up on and
// deleted.
func newHistoryCmd(configPath *string) *cobra.Command {
	var sinceFlag string
	var unsubmitted bool
	var limit int

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Shows this scanner's own local record of every host it has scanned",
		Long: "Reads the local scan audit log (scanAuditLogPath in config.yaml) - a permanent, append-only record written by " +
			"every scan this host runs, independent of the webserver. Useful for answering 'what did this scanner actually " +
			"touch, and when' without the dashboard, and for finding results that never reached it.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			since, err := parseSince(sinceFlag)
			if err != nil {
				return err
			}
			entries, err := auditlog.ReadSince(cfg.ScanAuditLogPath, since, unsubmitted)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				if unsubmitted {
					fmt.Println("Nothing unsubmitted - every scanned host in this window reached the webserver.")
				} else {
					fmt.Printf("No scans recorded in %s for this window.\n", cfg.ScanAuditLogPath)
				}
				return nil
			}
			// Newest first for reading, but trimmed to the newest
			// `limit` rather than the oldest - "the last 50 things that
			// happened" is what a history command is asked for.
			if limit > 0 && len(entries) > limit {
				entries = entries[len(entries)-limit:]
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "WHEN\tHOST\tOPEN PORTS\tSUBMITTED")
			for i := len(entries) - 1; i >= 0; i-- {
				e := entries[i]
				host := e.IP
				if e.Hostname != "" {
					host = fmt.Sprintf("%s (%s)", e.IP, e.Hostname)
				}
				state := "yes"
				if !e.Submitted {
					state = "NO"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", e.Time.Format("2006-01-02 15:04"), host, len(e.Ports), state)
			}
			w.Flush()
			fmt.Printf("\n%d host(s) shown from %s\n", len(entries), cfg.ScanAuditLogPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&sinceFlag, "since", "", "Only entries newer than this: a duration like 24h or 7d, or a date like 2026-09-01")
	cmd.Flags().BoolVar(&unsubmitted, "unsubmitted", false, "Only hosts whose results never reached the webserver")
	cmd.Flags().IntVar(&limit, "limit", 50, "Show at most this many of the newest entries. 0 shows everything")
	return cmd
}

// parseSince accepts both of the forms an operator actually reaches for,
// rather than only Go's own duration syntax: "24h"/"90m" and "7d" (which
// time.ParseDuration deliberately does not support), plus a plain date.
func parseSince(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if len(v) > 1 && v[len(v)-1] == 'd' {
		days, err := time.ParseDuration(v[:len(v)-1] + "h")
		if err == nil {
			return time.Now().Add(-days * 24), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("could not read --since %q: use a duration like 24h or 7d, or a date like 2006-01-02", v)
}
