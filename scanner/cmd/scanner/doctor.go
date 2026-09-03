package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/config"
	"porttorch/scanner/internal/pipeline"
	"porttorch/scanner/internal/version"
)

func newDoctorCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Checks the scanner's config, dependencies, and webserver connectivity before you run a real scan",
		// A failed check is an environment/config problem, not a
		// misused flag - showing the usage block for it would be noise.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(*configPath)
		},
	}
}

type checkStatus int

const (
	statusOK checkStatus = iota
	statusWarn
	statusFail
)

type check struct {
	name   string
	status checkStatus
	detail string
}

// runDoctor never returns on the first failure - it runs every check it
// can and prints a full report, since seeing "masscan is fine but nmap
// isn't on PATH and the webserver is unreachable" in one pass is far more
// useful than fixing issues one at a time across repeated runs.
func runDoctor(configPath string) error {
	var checks []check
	checks = append(checks, check{"scanner version", statusOK, version.Version})

	cfg, err := config.Load(configPath)
	if err != nil {
		detail := err.Error()
		// The plain "no such file or directory" from config.Load is
		// accurate but unhelpful on its own - the most common real cause
		// isn't a typo in --config, it's that install.sh only ever
		// populates config.yaml under the dedicated "porttorch" system
		// user's home (see install.sh / CLAUDE.md's "Scanner installer"),
		// so running the binary directly as your own login user resolves
		// a --config default (os.UserHomeDir()) that was never written to.
		// Scoped to exactly this error (errors.Is, not a substring check,
		// since config.Load wraps the underlying *fs.PathError with %w) so
		// a real permission or YAML-parse error still gets its own
		// unembellished message instead of a misleading hint.
		if errors.Is(err, fs.ErrNotExist) {
			detail += " - hint: if PortTorch was installed via install.sh, the config lives under the dedicated 'porttorch' system user's home, not yours; run this as that user (e.g. sudo -u porttorch porttorch doctor --config /var/lib/porttorch/.config/porttorch/config.yaml) or copy config.example.yaml to " + configPath + " for a standalone config"
		}
		checks = append(checks, check{"config file (" + configPath + ")", statusFail, detail})
		printChecks(checks)
		return fmt.Errorf("config could not be loaded")
	}
	checks = append(checks, check{"config file (" + configPath + ")", statusOK, "loaded"})

	// masscan and nmap are hard requirements - every scan needs both.
	// gowitness/Chrome, xfreerdp/Xvfb/import are optional (HTTP
	// screenshots and RDP screenshots are best-effort features), so their
	// absence is a warning, not a failure.
	checks = append(checks, checkPrivilegedBinary("masscan", cfg.MasscanPath, true)...)
	checks = append(checks, checkNmap(cfg)...)
	checks = append(checks, checkBinary("gowitness", cfg.GowitnessPath, false))
	checks = append(checks, checkChrome(cfg.ChromePath))
	checks = append(checks, checkBinary("xfreerdp (RDP screenshots)", cfg.XfreerdpPath, false))
	checks = append(checks, checkBinary("Xvfb (RDP screenshots)", cfg.XvfbPath, false))
	checks = append(checks, checkBinary("ImageMagick import (RDP screenshots)", cfg.ImportPath, false))
	checks = append(checks, checkBinary("tesseract (screenshot OCR)", cfg.TesseractPath, false))
	checks = append(checks, checkBinary("nuclei (web vulnerability scanning)", cfg.NucleiPath, false))
	checks = append(checks, checkNucleiTemplates())

	checks = append(checks, checkWebserver(cfg))

	printChecks(checks)

	for _, c := range checks {
		if c.status == statusFail {
			return fmt.Errorf("one or more required checks failed - see above")
		}
	}
	return nil
}

func printChecks(checks []check) {
	for _, c := range checks {
		var symbol string
		switch c.status {
		case statusOK:
			symbol = "[ OK ]"
		case statusWarn:
			symbol = "[WARN]"
		case statusFail:
			symbol = "[FAIL]"
		}
		fmt.Printf("%s %-45s %s\n", symbol, c.name, c.detail)
	}
}

// checkBinary confirms a binary is resolvable (either an absolute path
// that exists, or a bare command found on $PATH) and executable.
func checkBinary(label, configuredPath string, required bool) check {
	name := label + " (" + configuredPath + ")"
	resolved, err := exec.LookPath(configuredPath)
	if err != nil {
		status := statusWarn
		if required {
			status = statusFail
		}
		return check{name, status, "not found: " + err.Error()}
	}
	return check{name, statusOK, "found at " + resolved}
}

// checkPrivilegedBinary is checkBinary plus a best-effort check that the
// binary actually has the raw-socket access masscan/nmap need
// (cap_net_raw,cap_net_admin, or running as root) - a binary that's
// present but lacks this fails with a confusing permissions error only
// once a real scan is attempted, which this catches up front instead.
func checkPrivilegedBinary(label, configuredPath string, required bool) []check {
	binCheck := checkBinary(label, configuredPath, required)
	if binCheck.status == statusFail {
		return []check{binCheck}
	}

	if os.Geteuid() == 0 {
		return []check{binCheck, {label + " privileges", statusOK, "running as root"}}
	}

	resolved, err := exec.LookPath(configuredPath)
	if err != nil {
		return []check{binCheck}
	}
	getcapPath, err := exec.LookPath("getcap")
	if err != nil {
		return []check{binCheck, {label + " privileges", statusWarn, "getcap not available to verify - make sure cap_net_raw,cap_net_admin is set or run as root"}}
	}
	out, err := exec.Command(getcapPath, resolved).Output()
	if err != nil {
		return []check{binCheck, {label + " privileges", statusWarn, "could not run getcap: " + err.Error()}}
	}
	hasCaps := strings.Contains(string(out), "cap_net_raw") && strings.Contains(string(out), "cap_net_admin")
	if !hasCaps {
		return []check{binCheck, {
			label + " privileges", statusFail,
			fmt.Sprintf("missing cap_net_raw,cap_net_admin - run: sudo setcap cap_net_raw,cap_net_admin+eip %s", resolved),
		}}
	}
	return []check{binCheck, {label + " privileges", statusOK, "cap_net_raw,cap_net_admin set"}}
}

// checkNmap reports on however this scanner actually invokes nmap, which
// is one of two quite different setups.
//
// With nmapSudo off, nmap runs directly as this user and needs
// cap_net_raw/cap_net_admin like masscan does - the same check, plus a
// note that OS/device fingerprinting will be skipped, since those
// capabilities are not enough for -O (nmap refuses it for anyone but real
// root) and a permanently empty "OS" column otherwise looks like a bug in
// the scan rather than a property of the install.
//
// With nmapSudo on, nmapPath is install.sh's argument-validating wrapper:
// a plain shell script, which has no capabilities of its own and would
// fail that check for entirely the wrong reason. What matters there is
// whether "sudo -n" actually works unattended, so this runs a real
// one-port -O scan of loopback and reports what came back - the same
// thing a scan would do, rather than a proxy for it.
func checkNmap(cfg *config.Config) []check {
	if !cfg.NmapSudo {
		checks := checkPrivilegedBinary("nmap", cfg.NmapPath, true)
		if os.Geteuid() != 0 {
			checks = append(checks, check{
				"nmap OS detection", statusWarn,
				"skipped - nmap allows -O only for real root, and capabilities do not cover it; install.sh's sudo wrapper (nmapSudo) enables it",
			})
		}
		return checks
	}

	binCheck := checkBinary("nmap sudo wrapper", cfg.NmapPath, true)
	if binCheck.status == statusFail {
		return []check{binCheck}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", cfg.NmapPath, "-Pn", "--privileged", "-O", "-p", "1", "-oX", "-", "127.0.0.1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return []check{binCheck, {"nmap via sudo", statusFail, firstLine(detail)}}
	}
	if strings.Contains(string(out), "requires root privileges") {
		return []check{binCheck, {"nmap via sudo", statusFail, "sudo ran but nmap still reports it is not root"}}
	}
	return []check{binCheck, {"nmap via sudo", statusOK, "sudo -n works and OS detection (-O) is available"}}
}

// firstLine keeps a doctor row to one line - sudo and nmap both like to
// answer with several.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// checkChrome mirrors gowitness's own resolution order (explicit
// chromePath, then whatever chromedp/gowitness would find on $PATH) -
// google-chrome and chromium are both common depending on distro.
func checkChrome(chromePath string) check {
	if chromePath != "" {
		return checkBinary("Chrome/Chromium", chromePath, false)
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if resolved, err := exec.LookPath(name); err == nil {
			return check{"Chrome/Chromium (auto-detected)", statusOK, "found at " + resolved}
		}
	}
	return check{"Chrome/Chromium", statusWarn, "not found on $PATH - set chromePath in config.yaml, or HTTP screenshots will fail"}
}

// checkWebserver reuses GetExcludes (an existing, lightweight
// authenticated endpoint) rather than adding a health-check-only route -
// a successful call confirms both network reachability and that the
// configured API key is valid in one request.
func checkWebserver(cfg *config.Config) check {
	c, err := client.New(cfg)
	if err != nil {
		return check{"webserver client setup", statusFail, err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.GetExcludes(ctx); err != nil {
		return check{"webserver connectivity (" + cfg.WebserverURL + ")", statusFail, err.Error()}
	}
	return check{"webserver connectivity (" + cfg.WebserverURL + ")", statusOK, "reachable, api key valid"}
}

// nucleiTemplatesWarnDays mirrors the webserver's own Fleet Health
// threshold (NUCLEI_TEMPLATES_WARN_DAYS) - kept as its own small copy for
// the same reason compareSemver is duplicated across the two languages.
const nucleiTemplatesWarnDays = 30

// checkNucleiTemplates is deliberately separate from the nuclei binary
// check above: a resolvable binary says nothing about whether it has any
// templates to run, and the two fail independently. Worth its own line
// because the way this breaks is invisible otherwise - nuclei resolves
// its tree against the *invoking user's* home, so a `sudo
// nuclei-update-templates` run by an admin populates root's copy while
// the service, running as its own user, keeps finding nothing. That
// looks identical to "no findings on this fleet".
//
// Warning-only, never a failure: running without nuclei at all is a
// supported configuration (the whole stage is opt-in per scan), same as
// gowitness/RDP/tesseract above.
func checkNucleiTemplates() check {
	dir := pipeline.DefaultNucleiTemplatesDir()
	if dir == "" {
		return check{"nuclei templates", statusWarn, "could not determine this user's home directory"}
	}
	name := "nuclei templates (" + dir + ")"

	updated, err := pipeline.NucleiTemplatesUpdatedAt(dir)
	if err != nil {
		return check{name, statusWarn, "not found - run 'nuclei -update-templates' as this user, or trigger it from the dashboard (Scanner Agents -> Update templates)"}
	}

	days := int(time.Since(updated).Hours() / 24)
	detail := fmt.Sprintf("last updated %s (%dd ago)", updated.Format("2006-01-02"), days)
	if days >= nucleiTemplatesWarnDays {
		return check{name, statusWarn, detail + " - likely missing newer checks; refresh from the dashboard (Scanner Agents -> Update templates)"}
	}
	return check{name, statusOK, detail}
}
