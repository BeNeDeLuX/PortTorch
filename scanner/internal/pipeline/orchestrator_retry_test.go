package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeFlakyNmap replaces the stand-in nmap from writeFakeScanners with
// one whose enrichment call (-sV) fails for the addresses in failOnce on
// their first attempt only, and for every address when failAlways is set.
// The UDP probes (no -sV) always answer, so only the stage under test
// fails. Every enrichment call is logged as "<ip> ok|fail".
func writeFlakyNmap(t *testing.T, failOnce []string, failAlways bool) (nmap, logPath string) {
	t.Helper()
	dir := t.TempDir()
	nmap = filepath.Join(dir, "nmap")
	logPath = filepath.Join(dir, "nmap.log")
	script := fmt.Sprintf(`#!/bin/sh
for a; do last=$a; done
case " $* " in *" -sV "*) ;; *) printf '<?xml version="1.0"?><nmaprun></nmaprun>'; exit 0;; esac
fail=0
[ %q = yes ] && fail=1
for f in %s; do
  if [ "$f" = "$last" ] && [ ! -e %q/"$last" ]; then touch %q/"$last"; fail=1; fi
done
if [ $fail = 1 ]; then echo "$last fail" >> %q; echo "simulated failure" >&2; exit 1; fi
echo "$last ok" >> %q
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="%%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>' "$last"
`, map[bool]string{true: "yes", false: "no"}[failAlways], strings.Join(failOnce, " "), dir, dir, logPath, logPath)
	if err := os.WriteFile(nmap, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return nmap, logPath
}

func collectingCallbacks() (ProgressFunc, HostCompleteFunc, func() ([]string, string)) {
	var mu sync.Mutex
	var done []string
	var msgs []string
	return func(stage, msg string) {
			mu.Lock()
			msgs = append(msgs, msg)
			mu.Unlock()
		}, func(h HostResult) {
			mu.Lock()
			done = append(done, h.IP)
			mu.Unlock()
		}, func() ([]string, string) {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), done...), strings.Join(msgs, "\n")
		}
}

// The case the retry exists for: one host's nmap call fails once in a
// scan where everything else works. It is tried again after the others,
// comes through, and nothing is left for a resume.
func TestRunScanRetriesAFailedHostOnce(t *testing.T) {
	masscan, _, _ := writeFakeScanners(t, 0)
	nmap, nmapLog := writeFlakyNmap(t, []string{"10.9.4.0"}, false)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1, Concurrency: 2}
	onProgress, onHost, read := collectingCallbacks()
	cov := &ScanCoverage{}
	if _, err := RunScan(context.Background(), cfg, "10.9.0.0/20", "22", Excludes{}, nil, nil, nil, onProgress, onHost, cov); err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	done, msgs := read()
	if len(done) != 8 {
		t.Errorf("completed %d hosts, want all 8 including the retried one", len(done))
	}
	calls := readLines(t, nmapLog)
	if got := strings.Count(strings.Join(calls, " "), "10.9.4.0"); got != 2 {
		t.Errorf("10.9.4.0 was probed %d times, want 2 (fail, then retry): %v", got, calls)
	}
	if !strings.Contains(msgs, "retrying 1 host(s)") {
		t.Error("the retry should be announced in the progress log")
	}
	if got := cov.Remaining(); got != "" {
		t.Errorf("a retried host that succeeded leaves nothing to resume, got %q", got)
	}
}

// A scan of a single host still gets its retry: one failure says
// nothing about nmap itself.
func TestRunScanRetriesASingleHostScan(t *testing.T) {
	masscan, _, _ := writeFakeScanners(t, 0)
	nmap, _ := writeFlakyNmap(t, []string{"10.9.0.0"}, false)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1000, Concurrency: 2}
	onProgress, onHost, read := collectingCallbacks()
	if _, err := RunScan(context.Background(), cfg, "10.9.0.0/24", "22", Excludes{}, nil, nil, nil, onProgress, onHost, nil); err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if done, _ := read(); len(done) != 1 {
		t.Errorf("completed %v, want the one host after its retry", done)
	}
}

// Every host failing is nmap's problem, not the hosts': no second
// round, the scan fails as it always did, and the failed hosts stay in
// the remainder.
func TestRunScanDoesNotRetryWhenEveryHostFails(t *testing.T) {
	masscan, _, _ := writeFakeScanners(t, 0)
	nmap, nmapLog := writeFlakyNmap(t, nil, true)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1, Concurrency: 2}
	onProgress, onHost, read := collectingCallbacks()
	cov := &ScanCoverage{}
	_, err := RunScan(context.Background(), cfg, "10.9.0.0/20", "22", Excludes{}, nil, nil, nil, onProgress, onHost, cov)
	if err == nil || !strings.Contains(err.Error(), "all 8 host(s) failed") {
		t.Fatalf("err = %v, want the all-failed error", err)
	}
	if calls := readLines(t, nmapLog); len(calls) != 16 { // 8 lines of "<ip> fail"
		t.Errorf("nmap enrichment ran %d times, want 8 (no retry round)", len(calls)/2)
	}
	_, msgs := read()
	if !strings.Contains(msgs, "not retrying 8 failed host(s)") {
		t.Error("skipping the retry should be explained in the progress log")
	}
	if counts := cov.ProgressCounts(); counts == nil || counts.HostsProcessed != 8 {
		t.Errorf("progress should count every failed host as dealt with, got %+v", counts)
	}
	if got := cov.Remaining(); got == "" {
		t.Error("hosts that never got through nmap must stay in the remainder")
	}
}
