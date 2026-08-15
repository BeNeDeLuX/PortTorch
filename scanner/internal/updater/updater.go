// Package updater implements the scanner's self-update watcher (see
// CLAUDE.md's "Scanner Self-Update" plan): "serve" mode polls the
// webserver for an admin-triggered update request, downloads and
// checksum-verifies the target release binary from GitHub, atomically
// replaces its own binary on disk, and re-execs itself in place - no
// systemd restart needed, and no in-place write of the currently-
// executing file at any point.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"porttorch/scanner/internal/client"
	"porttorch/scanner/internal/version"
)

// httpTimeout bounds each individual webserver poll request - deliberately
// short, same as the cancel watcher's own per-check timeout. Binary/
// checksum downloads from GitHub get their own, longer timeout (see
// downloadTimeout) since a multi-megabyte binary over a slow link can
// easily exceed this.
const httpTimeout = 30 * time.Second
const downloadTimeout = 5 * time.Minute

// BusyChecker reports whether a scan is currently in progress. The update
// watcher skips a tick entirely rather than interrupting one -
// syscall.Exec replaces the whole process image, which would abruptly
// kill any in-progress masscan/nmap child with no clean "cancelled"
// status ever recorded (unlike the deliberate /cancel path). Updates
// aren't time-critical, so simply waiting for idle and re-checking next
// tick costs nothing. Satisfied by *api.Server's IsScanning method.
type BusyChecker interface {
	IsScanning() bool
}

// updateClient is the subset of *client.Client this package needs -
// defined as an interface (rather than depending on the concrete type
// directly in checkAndApply) so tests can inject a fake without a real
// HTTP server, matching this codebase's general "unit-test the pure
// logic, integration-test the real wiring separately" split.
type updateClient interface {
	CheckUpdateRequested(ctx context.Context) (bool, error)
	GetScannerRelease(ctx context.Context) (client.ReleaseInfo, error)
	ReportUpdateOutcome(ctx context.Context, succeeded bool, failureReason string) error
}

// StartUpdateWatcher blocks until ctx is done - same ticker-loop shape as
// api.Server's StartCancelWatcher/StartPolling, and typically started
// alongside them as its own goroutine from "serve" mode only (scan/menu
// are one-shot processes with nothing polling in the background, so they
// can never self-update).
func StartUpdateWatcher(ctx context.Context, c *client.Client, busy BusyChecker, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndApply(ctx, c, busy, log, defaultBinaryPath, defaultDownloadRelease, defaultReplaceAndExec)
		}
	}
}

// The last three parameters are injected purely so checkAndApply's
// control flow (busy-skip, not-actually-newer skip, failure reporting)
// can be unit-tested without touching the real filesystem, a real GitHub
// release, or actually re-exec-ing the test binary. Production callers
// always use the default* implementations below via StartUpdateWatcher.
func checkAndApply(
	ctx context.Context,
	c updateClient,
	busy BusyChecker,
	log *slog.Logger,
	binaryPath func() (string, error),
	downloadRelease func(ctx context.Context, tag, releaseURL, arch string) (string, error),
	replaceAndExec func(binPath, downloadedPath string) error,
) {
	checkCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	requested, err := c.CheckUpdateRequested(checkCtx)
	cancel()
	if err != nil {
		log.Error("checking scanner update request failed", "event", "update_watch.check_failed", "error", err.Error())
		return
	}
	if !requested {
		return
	}

	if busy.IsScanning() {
		log.Info("scanner update requested but a scan is in progress, deferring to next check", "event", "update_watch.deferred")
		return
	}

	binPath, err := binaryPath()
	if err != nil {
		reportFailure(ctx, c, log, fmt.Sprintf("resolving own executable path: %v", err))
		return
	}
	if err := checkWritable(binPath); err != nil {
		reportFailure(ctx, c, log, fmt.Sprintf("binary or its directory not writable - re-run install.sh: %v", err))
		return
	}

	relCtx, relCancel := context.WithTimeout(ctx, httpTimeout)
	release, err := c.GetScannerRelease(relCtx)
	relCancel()
	if err != nil {
		reportFailure(ctx, c, log, fmt.Sprintf("fetching latest scanner release info: %v", err))
		return
	}
	if release.LatestVersion == "" || release.LatestTag == "" {
		reportFailure(ctx, c, log, "webserver has no cached scanner release info yet")
		return
	}
	if compareSemver(release.LatestVersion, version.Version) <= 0 {
		// Not actually newer - a stale or already-applied request (e.g.
		// this scanner already updated itself on a prior tick, or the
		// admin re-triggered after the fact). Report success so it's
		// cleared rather than retried forever.
		succCtx, succCancel := context.WithTimeout(ctx, httpTimeout)
		_ = c.ReportUpdateOutcome(succCtx, true, "")
		succCancel()
		log.Info("scanner update request already satisfied", "event", "update_watch.already_current", "current_version", version.Version, "latest_version", release.LatestVersion)
		return
	}

	downloaded, err := downloadRelease(ctx, release.LatestTag, release.ReleaseURL, runtime.GOARCH)
	if err != nil {
		reportFailure(ctx, c, log, err.Error())
		return
	}
	defer os.Remove(downloaded)

	if err := replaceAndExec(binPath, downloaded); err != nil {
		reportFailure(ctx, c, log, fmt.Sprintf("installing new binary: %v", err))
		return
	}

	succCtx, succCancel := context.WithTimeout(ctx, httpTimeout)
	_ = c.ReportUpdateOutcome(succCtx, true, "")
	succCancel()
	log.Info("scanner self-update succeeded, re-executing", "event", "update_watch.succeeded", "old_version", version.Version, "new_version", release.LatestVersion)

	execErr := syscall.Exec(binPath, os.Args, os.Environ())
	// Only reached if Exec itself failed to even start the new process
	// image (e.g. a permission error) - on success this process image is
	// replaced outright and nothing after this line ever runs.
	log.Error("re-exec after self-update failed - the new binary is installed but this process is still running the old one; restart the service manually", "event", "update_watch.reexec_failed", "error", execErr.Error())
}

func reportFailure(ctx context.Context, c updateClient, log *slog.Logger, reason string) {
	log.Error("scanner self-update failed", "event", "update_watch.failed", "reason", reason)
	failCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	if err := c.ReportUpdateOutcome(failCtx, false, reason); err != nil {
		log.Error("reporting scanner update failure to webserver also failed", "event", "update_watch.report_failed", "error", err.Error())
	}
}

func defaultBinaryPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// checkWritable defensively confirms the binary and its containing
// directory (os.Rename below needs to create/replace an entry in that
// directory) are actually writable *before* spending time downloading
// anything. A real, confirmed-in-production gap: chowning the binary
// file to the service user is not enough on its own - /usr/local/bin
// itself is root:root 0755 on a stock Debian install, so the directory
// check here failed on every install.sh-managed deployment until
// install.sh also started granting the service user a POSIX ACL on
// $BIN_PATH's directory (setfacl, not a chown/chmod of the shared
// directory itself - see install.sh's grant_bin_dir_access). A
// manually-managed deployment still needs the equivalent done by hand.
// Failing fast here with a clear message beats a confusing error
// partway through installing the new binary either way.
func checkWritable(binPath string) error {
	const wOK = 2 // syscall.Access's W_OK - not exported as a named const on linux/amd64's syscall package
	if err := syscall.Access(binPath, wOK); err != nil {
		return fmt.Errorf("%s is not writable by this process: %w", binPath, err)
	}
	dir := filepath.Dir(binPath)
	if err := syscall.Access(dir, wOK); err != nil {
		return fmt.Errorf("%s is not writable by this process: %w", dir, err)
	}
	return nil
}

// defaultDownloadRelease mirrors install.sh's download_release_binary
// exactly: fetch the arch-specific binary asset plus SHA256SUMS from the
// GitHub release, verify the checksum, and only return a path to the
// verified file - fail-closed on any network error or mismatch, same as
// install.sh's own behavior (there, a failure falls back to building from
// source; here, there is no fallback - it's reported as a failed update
// attempt instead).
func defaultDownloadRelease(ctx context.Context, tag, releaseURL, arch string) (string, error) {
	repoSlug, err := repoSlugFromReleaseURL(releaseURL)
	if err != nil {
		return "", fmt.Errorf("determining GitHub repo from release URL: %w", err)
	}

	assetName := "porttorch-linux-" + arch
	binURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repoSlug, tag, assetName)
	sumsURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", repoSlug, tag)

	dlCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	binData, err := httpGetBytes(dlCtx, binURL)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", assetName, err)
	}
	sumsData, err := httpGetBytes(dlCtx, sumsURL)
	if err != nil {
		return "", fmt.Errorf("downloading SHA256SUMS: %w", err)
	}

	if err := verifyChecksum(binData, string(sumsData), assetName); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp("", "porttorch-update-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file for downloaded binary: %w", err)
	}
	defer tmp.Close()
	if _, err := tmp.Write(binData); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("writing downloaded binary to temp file: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("setting downloaded binary executable: %w", err)
	}
	return tmp.Name(), nil
}

func httpGetBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// verifyChecksum parses a `sha256sum`-style SHA256SUMS file (lines of
// "<hex digest>  <filename>") and confirms data's digest matches the
// entry for assetName - exported logic-wise via being a package-level
// pure function so it's directly unit-testable with hand-built inputs,
// no real download needed.
func verifyChecksum(data []byte, sumsContent, assetName string) error {
	var expected string
	for _, line := range strings.Split(sumsContent, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == assetName || fields[1] == "*"+assetName {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("no checksum entry for %s in SHA256SUMS", assetName)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetName, expected, actual)
	}
	return nil
}

// repoSlugFromReleaseURL extracts "owner/repo" from a GitHub release's
// html_url (e.g. "https://github.com/BeNeDeLuX/PortTorch/releases/tag/scanner-v0.5.0")
// - the webserver's cached release row only stores this URL (see
// scannerUpdate/githubSync.ts), not a separate repo-slug field, since the
// URL already fully determines it and install.sh's own equivalent
// (release_repo_slug) derives it from a different source (git remote)
// for the same underlying "owner/repo" value.
func repoSlugFromReleaseURL(releaseURL string) (string, error) {
	const marker = "github.com/"
	idx := strings.Index(releaseURL, marker)
	if idx == -1 {
		return "", fmt.Errorf("release URL %q doesn't look like a github.com URL", releaseURL)
	}
	rest := releaseURL[idx+len(marker):]
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("couldn't parse owner/repo from release URL %q", releaseURL)
	}
	return parts[0] + "/" + parts[1], nil
}

// compareSemver does a plain X.Y.Z numeric compare, mirroring the
// webserver's own scannerUpdate/githubSync.ts compareSemver exactly (same
// "no pre-release/build-metadata suffix" assumption, matching how this
// scanner's own version.go and the scanner-vX.Y.Z release tag convention
// are actually formatted). Returns >0 if a > b, <0 if a < b, 0 if equal.
func compareSemver(a, b string) int {
	pa := parseSemverParts(a)
	pb := parseSemverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] - pb[i]
		}
	}
	return 0
}

func parseSemverParts(v string) [3]int {
	var out [3]int
	parts := strings.SplitN(v, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}

// defaultReplaceAndExec atomically installs the downloaded, already-
// checksum-verified binary at downloadedPath over binPath - a temp file
// in the *same directory* as binPath (so the rename is guaranteed atomic,
// same filesystem) followed by os.Rename, never an in-place truncate+
// write of the currently-executing file. Re-exec itself happens in
// checkAndApply, not here, since that also needs to report success to the
// webserver first.
func defaultReplaceAndExec(binPath, downloadedPath string) error {
	targetDir := filepath.Dir(binPath)
	tmpPath := filepath.Join(targetDir, ".porttorch-update-tmp")

	src, err := os.Open(downloadedPath)
	if err != nil {
		return fmt.Errorf("opening downloaded binary: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating staged binary in %s: %w", targetDir, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("staging downloaded binary: %w", err)
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing staged binary: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("setting staged binary executable: %w", err)
	}
	if err := os.Rename(tmpPath, binPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming staged binary into place: %w", err)
	}
	return nil
}
