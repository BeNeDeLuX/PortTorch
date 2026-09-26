package pipeline

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// NmapCmd is how this scanner invokes nmap: the binary to run, and
// whether to go through sudo to get real root for it.
//
// It exists because two nmap features the pipeline wants - -O
// (OS/device fingerprinting) and -sS (needed whenever a scan includes UDP
// ports, since -sU alone can't also cover the TCP ones) - are refused
// outright for anyone but uid 0. That refusal is nmap's own euid check,
// not a kernel one: the cap_net_raw/cap_net_admin capabilities install.sh
// grants are enough for every other nmap mode but not for these, verified
// by running them as the unprivileged service user on a host where those
// capabilities were confirmed set. So a scanner installed the normal way
// (systemd, unprivileged service user) could never classify an operating
// system at all, and every UDP scan failed at launch.
//
// Sudo defaults to false, which reproduces the previous behaviour exactly
// - the command line built for a non-sudo scanner is byte-identical to
// what it always was, and a config that doesn't mention nmapSudo keeps
// running unprivileged nmap without -O.
type NmapCmd struct {
	Path string
	// Sudo runs Path through "sudo -n". install.sh points Path at its
	// argument-validating wrapper (/usr/local/bin/porttorch-nmap) and
	// grants exactly that one command in a sudoers drop-in - never nmap
	// itself, which would be a full root shell by way of "--script
	// /tmp/anything.nse".
	Sudo bool

	// HostTimeoutSeconds / ScriptTimeoutSeconds are nmap's own
	// --host-timeout and --script-timeout for the enrichment pass. 0
	// leaves the respective flag off.
	HostTimeoutSeconds   int
	ScriptTimeoutSeconds int
}

// How long to wait for a cancelled nmap to actually go away before
// giving up on it and letting the worker continue. Only reached when
// SIGTERM did not work, which in practice means something is wedged
// beyond our reach.
const nmapCancelGrace = 10 * time.Second

// command builds the process to run. -n so sudo never blocks a scan
// waiting on a password prompt that nothing is there to answer: a
// misconfigured sudoers entry fails immediately and visibly instead.
//
// **Cancellation has to be SIGTERM, and it has to reach the process
// group.** Go's CommandContext default is SIGKILL to the direct child,
// which through sudo is sudo itself - and SIGKILL cannot be caught, so
// sudo dies without passing anything on and the root nmap underneath it
// is orphaned. Worse, that orphan still holds the stdout pipe this
// process is reading, so cmd.Wait never returns and the worker goroutine
// is wedged for the life of the process: the scan stops producing output
// and can never finish. Measured, not reasoned about - with SIGKILL the
// grandchild survived and Wait blocked indefinitely; with SIGTERM sudo
// forwarded it, the child exited, and Wait returned at once.
//
// An unprivileged scanner cannot signal the root nmap directly at all
// (EPERM), so sudo forwarding the signal is the only route there is.
// WaitDelay is the backstop for the case where it still does not go:
// Wait returns anyway rather than holding the worker forever.
func (n NmapCmd) command(ctx context.Context, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if n.Sudo {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"-n", n.Path}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, n.Path, args...)
	}
	// Its own process group, so one signal covers sudo and whatever it
	// started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = nmapCancelGrace
	return cmd
}

// elevated reports whether nmap will actually run with the privileges its
// root-only features need - either because this process is already root
// (the CLI/TUI run interactively under sudo, typically) or because it
// goes through the sudo wrapper.
func (n NmapCmd) elevated() bool {
	return n.Sudo || os.Geteuid() == 0
}

// describe is what doctor and error messages show, so "which nmap did it
// actually try to run" is answerable from a log line alone.
func (n NmapCmd) describe() string {
	if n.Sudo {
		return "sudo -n " + n.Path
	}
	return n.Path
}

// nmapCmd is the single place the pipeline's own config turns into one.
func (c Config) nmapCmd() NmapCmd {
	return NmapCmd{
		Path:                 c.NmapPath,
		Sudo:                 c.NmapSudo,
		HostTimeoutSeconds:   c.NmapHostTimeoutSeconds,
		ScriptTimeoutSeconds: c.NmapScriptTimeoutSeconds,
	}
}
