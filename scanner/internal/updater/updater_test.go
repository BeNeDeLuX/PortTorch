package updater

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"porttorch/scanner/internal/client"
)

// writableFakeBinary creates a real, writable file in a real, writable
// temp directory and returns its path - checkAndApply's checkWritable
// step is a real filesystem check (deliberately not injected/mocked, so
// the tests below exercise the actual permission-checking code), so
// these tests need a path that genuinely exists and is genuinely
// writable rather than an arbitrary string.
func writableFakeBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "porttorch")
	if err := os.WriteFile(path, []byte("fake"), 0o755); err != nil {
		t.Fatalf("creating fake binary: %v", err)
	}
	return path
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("fake binary contents")
	// sha256("fake binary contents")
	const correctSum = "8f085fe997ff530dffd03f012bbbeec8fac8af916bc19c0a1c98bca5a9c1703f"

	cases := []struct {
		name        string
		sums        string
		assetName   string
		wantErr     bool
		errContains string
	}{
		{"matching", correctSum + "  porttorch-linux-amd64\n", "porttorch-linux-amd64", false, ""},
		{"matching with leading star (binary mode marker)", correctSum + "  *porttorch-linux-amd64\n", "porttorch-linux-amd64", false, ""},
		{"other entries present", "deadbeef  other-file\n" + correctSum + "  porttorch-linux-amd64\n", "porttorch-linux-amd64", false, ""},
		{"missing entry", "deadbeef  porttorch-linux-arm64\n", "porttorch-linux-amd64", true, "no checksum entry"},
		{"mismatched digest", "0000000000000000000000000000000000000000000000000000000000000000  porttorch-linux-amd64\n", "porttorch-linux-amd64", true, "checksum mismatch"},
		{"empty sums file", "", "porttorch-linux-amd64", true, "no checksum entry"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyChecksum(data, tc.sums, tc.assetName)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantErr && err != nil && tc.errContains != "" {
				if !contains(err.Error(), tc.errContains) {
					t.Errorf("error %q doesn't contain %q", err.Error(), tc.errContains)
				}
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestRepoSlugFromReleaseURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{"tag url", "https://github.com/BeNeDeLuX/PortTorch/releases/tag/scanner-v0.5.0", "BeNeDeLuX/PortTorch", false},
		{"releases root", "https://github.com/owner/repo/releases", "owner/repo", false},
		{"not a github url", "https://gitlab.com/owner/repo/releases/tag/v1", "", true},
		{"malformed - no repo segment", "https://github.com/owner", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repoSlugFromReleaseURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got slug %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("repoSlugFromReleaseURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign only, checked via > 0 / < 0 / == 0
	}{
		{"0.5.0", "0.4.4", 1},
		{"0.4.4", "0.5.0", -1},
		{"0.4.4", "0.4.4", 0},
		{"1.0.0", "0.99.99", 1},
		{"0.4.10", "0.4.9", 1}, // numeric, not lexicographic, comparison
		{"0.4", "0.4.0", 0},    // missing patch defaults to 0
	}

	for _, tc := range cases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got := compareSemver(tc.a, tc.b)
			switch {
			case tc.want > 0 && got <= 0:
				t.Errorf("compareSemver(%q, %q) = %d, want > 0", tc.a, tc.b, got)
			case tc.want < 0 && got >= 0:
				t.Errorf("compareSemver(%q, %q) = %d, want < 0", tc.a, tc.b, got)
			case tc.want == 0 && got != 0:
				t.Errorf("compareSemver(%q, %q) = %d, want 0", tc.a, tc.b, got)
			}
		})
	}
}

// fakeUpdateClient lets checkAndApply's control flow be tested without a
// real HTTP server - each field is a canned response/error, and calls are
// counted so tests can assert e.g. "GetScannerRelease was never called
// because the busy check short-circuited first".
type fakeUpdateClient struct {
	requested      bool
	requestedErr   error
	release        client.ReleaseInfo
	releaseErr     error
	outcomeCalls   int
	lastSucceeded  bool
	lastReason     string
	releaseCalls   int
	requestedCalls int
}

func (f *fakeUpdateClient) CheckUpdateRequested(ctx context.Context) (bool, error) {
	f.requestedCalls++
	return f.requested, f.requestedErr
}

func (f *fakeUpdateClient) GetScannerRelease(ctx context.Context) (client.ReleaseInfo, error) {
	f.releaseCalls++
	return f.release, f.releaseErr
}

func (f *fakeUpdateClient) ReportUpdateOutcome(ctx context.Context, succeeded bool, reason string) error {
	f.outcomeCalls++
	f.lastSucceeded = succeeded
	f.lastReason = reason
	return nil
}

type fakeBusy struct{ busy bool }

func (f fakeBusy) IsScanning() bool { return f.busy }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCheckAndApply_NoUpdateRequested(t *testing.T) {
	c := &fakeUpdateClient{requested: false}
	checkAndApply(context.Background(), c, fakeBusy{busy: false}, discardLogger(),
		func() (string, error) { t.Fatal("binaryPath should not be called"); return "", nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			t.Fatal("downloadRelease should not be called")
			return "", nil
		},
		func(binPath, downloadedPath string) error { t.Fatal("replaceAndExec should not be called"); return nil },
	)
	if c.releaseCalls != 0 {
		t.Errorf("GetScannerRelease should not have been called, was called %d times", c.releaseCalls)
	}
	if c.outcomeCalls != 0 {
		t.Errorf("ReportUpdateOutcome should not have been called, was called %d times", c.outcomeCalls)
	}
}

func TestCheckAndApply_SkipsWhenBusy(t *testing.T) {
	c := &fakeUpdateClient{requested: true}
	checkAndApply(context.Background(), c, fakeBusy{busy: true}, discardLogger(),
		func() (string, error) { t.Fatal("binaryPath should not be called while busy"); return "", nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			t.Fatal("downloadRelease should not be called while busy")
			return "", nil
		},
		func(binPath, downloadedPath string) error {
			t.Fatal("replaceAndExec should not be called while busy")
			return nil
		},
	)
	if c.releaseCalls != 0 {
		t.Errorf("GetScannerRelease should not have been called while busy, was called %d times", c.releaseCalls)
	}
	if c.outcomeCalls != 0 {
		t.Errorf("ReportUpdateOutcome should not have been called while busy (re-checked next tick), was called %d times", c.outcomeCalls)
	}
}

func TestCheckAndApply_CheckRequestFails(t *testing.T) {
	c := &fakeUpdateClient{requestedErr: errors.New("network error")}
	checkAndApply(context.Background(), c, fakeBusy{busy: false}, discardLogger(),
		func() (string, error) { t.Fatal("binaryPath should not be called on check failure"); return "", nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			t.Fatal("downloadRelease should not be called on check failure")
			return "", nil
		},
		func(binPath, downloadedPath string) error {
			t.Fatal("replaceAndExec should not be called on check failure")
			return nil
		},
	)
	if c.outcomeCalls != 0 {
		t.Errorf("ReportUpdateOutcome should not have been called on a mere poll failure, was called %d times", c.outcomeCalls)
	}
}

func TestCheckAndApply_AlreadyCurrentReportsSuccessWithoutDownloading(t *testing.T) {
	// version.Version in test builds defaults to whatever's hardcoded in
	// version.go - simulate "latest" being the same or older, which must
	// never trigger a download/replace, only a success report (clears a
	// stale/already-applied request rather than retrying forever).
	c := &fakeUpdateClient{requested: true, release: client.ReleaseInfo{LatestVersion: "0.0.1", LatestTag: "scanner-v0.0.1", ReleaseURL: "https://github.com/o/r/releases/tag/scanner-v0.0.1"}}
	downloadCalled := false
	binPath := writableFakeBinary(t)
	checkAndApply(context.Background(), c, fakeBusy{busy: false}, discardLogger(),
		func() (string, error) { return binPath, nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			downloadCalled = true
			return "", nil
		},
		func(binPath, downloadedPath string) error {
			t.Fatal("replaceAndExec should not be called when not actually newer")
			return nil
		},
	)
	if downloadCalled {
		t.Error("downloadRelease should not have been called for a not-newer version")
	}
	if c.outcomeCalls != 1 || !c.lastSucceeded {
		t.Errorf("expected exactly one succeeded outcome report, got calls=%d succeeded=%v", c.outcomeCalls, c.lastSucceeded)
	}
}

func TestCheckAndApply_DownloadFailureReportsFailure(t *testing.T) {
	c := &fakeUpdateClient{requested: true, release: client.ReleaseInfo{LatestVersion: "99.0.0", LatestTag: "scanner-v99.0.0", ReleaseURL: "https://github.com/o/r/releases/tag/scanner-v99.0.0"}}
	binPath := writableFakeBinary(t)
	checkAndApply(context.Background(), c, fakeBusy{busy: false}, discardLogger(),
		func() (string, error) { return binPath, nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			return "", errors.New("checksum mismatch")
		},
		func(binPath, downloadedPath string) error {
			t.Fatal("replaceAndExec should not be called after a download failure")
			return nil
		},
	)
	if c.outcomeCalls != 1 || c.lastSucceeded {
		t.Errorf("expected exactly one failed outcome report, got calls=%d succeeded=%v reason=%q", c.outcomeCalls, c.lastSucceeded, c.lastReason)
	}
}

func TestCheckAndApply_SuccessPathReportsSuccessBeforeExec(t *testing.T) {
	c := &fakeUpdateClient{requested: true, release: client.ReleaseInfo{LatestVersion: "99.0.0", LatestTag: "scanner-v99.0.0", ReleaseURL: "https://github.com/o/r/releases/tag/scanner-v99.0.0"}}
	replaceCalled := false
	binPath := writableFakeBinary(t)
	// Note: checkAndApply's real tail does syscall.Exec(binPath, ...) on
	// success - binPath here is a real file but not a valid ELF binary,
	// so execve fails with ENOEXEC and control returns normally (Exec
	// only replaces the process image on success) rather than replacing
	// this test process. The actual re-exec behavior against a real
	// binary is verified manually per the plan's "Verification" section
	// (a real disposable install), not exercised here.
	checkAndApply(context.Background(), c, fakeBusy{busy: false}, discardLogger(),
		func() (string, error) { return binPath, nil },
		func(ctx context.Context, tag, releaseURL, arch string) (string, error) {
			return "/tmp/fake-downloaded-binary", nil
		},
		func(binPath, downloadedPath string) error {
			replaceCalled = true
			return nil
		},
	)
	if !replaceCalled {
		t.Fatal("replaceAndExec should have been called")
	}
	if c.outcomeCalls != 1 || !c.lastSucceeded {
		t.Errorf("expected exactly one succeeded outcome report, got calls=%d succeeded=%v", c.outcomeCalls, c.lastSucceeded)
	}
}
