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

func mustRanges(t *testing.T, spec string) []ipv4Range {
	t.Helper()
	rs, ok := parseIPv4Ranges(spec)
	if !ok {
		t.Fatalf("parseIPv4Ranges(%q) failed", spec)
	}
	return rs
}

func TestParseIPv4RangesAcceptsEveryForm(t *testing.T) {
	got := formatRanges(mergeRanges(mustRanges(t, "10.0.0.5, 10.0.1.0/30 ,10.0.2.1-10.0.2.3")))
	want := "10.0.0.5,10.0.1.0-10.0.1.3,10.0.2.1-10.0.2.3"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Anything the planner cannot count exactly is left to masscan as-is,
	// rather than planned around a guess.
	for _, spec := range []string{"web.internal", "2001:db8::1", "10.0.0.0/24,host.lan", "10.0.0.9-10.0.0.1", ""} {
		if _, ok := parseIPv4Ranges(spec); ok {
			t.Errorf("parseIPv4Ranges(%q) should refuse", spec)
		}
	}
}

func TestMergeAndSubtractRanges(t *testing.T) {
	merged := mergeRanges(mustRanges(t, "10.0.0.10-10.0.0.20,10.0.0.0-10.0.0.9,10.0.0.15-10.0.0.30"))
	if got := formatRanges(merged); got != "10.0.0.0-10.0.0.30" {
		t.Errorf("adjacent and overlapping ranges should merge, got %q", got)
	}

	left := subtractRanges(mustRanges(t, "10.0.0.0/24"), mustRanges(t, "10.0.0.0/26,10.0.0.100,10.0.0.250-10.0.1.5"))
	if got := formatRanges(left); got != "10.0.0.64-10.0.0.99,10.0.0.101-10.0.0.249" {
		t.Errorf("subtract = %q", got)
	}
	if got := subtractRanges(mustRanges(t, "10.0.0.0/24"), mustRanges(t, "10.0.0.0/16")); len(got) != 0 {
		t.Errorf("a fully excluded target should leave nothing, got %v", got)
	}
}

func TestPlanLeavesSmallOrShortScansAsOnePass(t *testing.T) {
	cases := []struct {
		name  string
		spec  string
		ports int
		rate  int
	}{
		// The block floor is a /24: a small range with a huge port list
		// stays one pass, exactly as it always ran.
		{"one /24, every port", "10.0.0.0/24", 65535, 1000},
		// Big, but quick enough that splitting buys nothing.
		{"a /16 on one port", "10.0.0.0/16", 1, 1000},
		{"hostname", "web.internal", 1000, 100},
		{"IPv6", "2001:db8::1", 1000, 100},
	}
	for _, c := range cases {
		if plan := planIPv4Chunks(c.spec, nil, c.ports, c.rate); plan != nil {
			t.Errorf("%s: expected one pass, got %d blocks", c.name, len(plan.blocks))
		}
	}
}

func TestPlanSplitsIntoContiguousBoundedBlocks(t *testing.T) {
	// 65536 addresses x 100 ports at 1000 pps is ~1.8h. A 5-minute block
	// is 3000 addresses, rounded up to whole /24s: 3072.
	plan := planIPv4Chunks("10.20.0.0/16", nil, 100, 1000)
	if plan == nil {
		t.Fatal("expected the target to be split")
	}
	if plan.perBlock != 3072 {
		t.Errorf("perBlock = %d, want 3072", plan.perBlock)
	}
	if len(plan.blocks) != 22 {
		t.Errorf("blocks = %d, want 22 (21 full plus a 1024-address tail)", len(plan.blocks))
	}

	// Together the blocks are exactly the target - nothing skipped,
	// nothing scanned twice.
	var all []ipv4Range
	var total uint64
	for _, b := range plan.blocks {
		var n uint64
		for _, r := range b {
			n += r.size()
		}
		if n > plan.perBlock {
			t.Errorf("block of %d addresses exceeds %d", n, plan.perBlock)
		}
		total += n
		all = append(all, b...)
	}
	if total != 65536 {
		t.Errorf("blocks cover %d addresses, want 65536", total)
	}
	if got := formatRanges(mergeRanges(all)); got != "10.20.0.0-10.20.255.255" {
		t.Errorf("blocks merge to %q", got)
	}
}

func TestPlanSubtractsExcludesBeforeSplitting(t *testing.T) {
	// Half the /16 is excluded, so the blocks cover only the other half,
	// and no block is spent on addresses masscan would skip anyway.
	plan := planIPv4Chunks("10.20.0.0/16", []string{"10.20.0.0/17", "2001:db8::/64"}, 100, 1000)
	if plan == nil {
		t.Fatal("expected a split")
	}
	var all []ipv4Range
	for _, b := range plan.blocks {
		all = append(all, b...)
	}
	if got := formatRanges(mergeRanges(all)); got != "10.20.128.0-10.20.255.255" {
		t.Errorf("blocks should cover only the non-excluded half, got %q", got)
	}
}

func TestCoverageRemaining(t *testing.T) {
	var nilCov *ScanCoverage
	if nilCov.Remaining() != "" {
		t.Error("a nil coverage has nothing to offer")
	}
	if (&ScanCoverage{}).Remaining() != "" {
		t.Error("a scan that never planned discovery covered nothing, and is a plain rescan rather than a resume")
	}

	// One pass that never finished: the target exactly as typed, which
	// keeps a hostname or an IPv6 list intact.
	c := &ScanCoverage{}
	c.plan("web.internal", map[string]string{"10.0.0.7": "web.internal"}, nil)
	if got := c.Remaining(); got != "web.internal" {
		t.Errorf("unfinished single pass = %q", got)
	}

	// Discovery finished; one host completed, two did not. The hostname
	// comes back for the resolved address, so the resume still gets SNI.
	c.blockDiscovered(0, []string{"10.0.0.7", "10.0.0.8", "10.0.0.9"})
	c.hostDone("10.0.0.9")
	if got := c.Remaining(); got != "10.0.0.8,web.internal" {
		t.Errorf("after discovery = %q", got)
	}
	c.hostDone("10.0.0.7")
	c.hostDone("10.0.0.8")
	if got := c.Remaining(); got != "" {
		t.Errorf("everything done should leave nothing, got %q", got)
	}

	// Several blocks: the unfinished blocks plus the unfinished hosts,
	// merged into as few ranges as they allow.
	m := &ScanCoverage{}
	m.plan("10.1.0.0/22", nil, [][]ipv4Range{
		mustRanges(t, "10.1.0.0/24"), mustRanges(t, "10.1.1.0/24"),
		mustRanges(t, "10.1.2.0/24"), mustRanges(t, "10.1.3.0/24"),
	})
	m.blockDiscovered(0, []string{"10.1.0.5"})
	m.blockDiscovered(1, []string{"10.1.1.255"})
	m.hostDone("10.1.0.5")
	if got := m.Remaining(); got != "10.1.1.255-10.1.3.255" {
		t.Errorf("multi-block remaining = %q", got)
	}
}

// writeFakeScanners puts a stand-in masscan and nmap in a temp dir. The
// masscan logs each target it is given and reports that target's first
// address as having 22/tcp open; from invocation stallAt onwards it hangs
// instead, standing in for a pass still running when the scan is
// cancelled. nmap confirms 22 on whatever address it was given.
func writeFakeScanners(t *testing.T, stallAt int) (masscan, nmap, logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "masscan.log")
	masscan = filepath.Join(dir, "masscan")
	nmap = filepath.Join(dir, "nmap")

	masscanScript := fmt.Sprintf(`#!/bin/sh
target=$1
out=""
prev=""
for a; do [ "$prev" = "-oJ" ] && out=$a; prev=$a; done
echo "$target" >> %q
n=$(wc -l < %q)
if [ %d -gt 0 ] && [ "$n" -ge %d ]; then exec sleep 30; fi
first=${target%%%%,*}; first=${first%%%%-*}; first=${first%%%%/*}
printf '[{"ip":"%%s","ports":[{"port":22,"proto":"tcp","status":"open"}]}]' "$first" > "$out"
`, logPath, logPath, stallAt, stallAt)
	nmapScript := `#!/bin/sh
for a; do last=$a; done
printf '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>' "$last"
`
	if err := os.WriteFile(masscan, []byte(masscanScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nmap, []byte(nmapScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return masscan, nmap, logPath
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

// A /20 on one port at 1 pps is ~68 minutes, so it splits into eight
// 512-address blocks. Every block must reach masscan, every host found
// must come out the other end, and nothing is left over.
func TestRunScanDiscoversInBlocksAndStreams(t *testing.T) {
	masscan, nmap, logPath := writeFakeScanners(t, 0)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1, Concurrency: 2}

	var mu sync.Mutex
	var completed []string
	var messages []string
	cov := &ScanCoverage{}
	result, err := RunScan(context.Background(), cfg, "10.9.0.0/20", "22", Excludes{}, nil, nil, nil,
		func(stage, msg string) {
			mu.Lock()
			messages = append(messages, msg)
			mu.Unlock()
		},
		func(h HostResult) {
			mu.Lock()
			completed = append(completed, h.IP)
			mu.Unlock()
		},
		cov,
	)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	calls := readLines(t, logPath)
	if len(calls) != 8 {
		t.Fatalf("masscan ran %d times, want 8 blocks: %v", len(calls), calls)
	}
	if calls[0] != "10.9.0.0-10.9.1.255" || calls[7] != "10.9.14.0-10.9.15.255" {
		t.Errorf("unexpected block specs: first %q, last %q", calls[0], calls[7])
	}
	if len(completed) != 8 || result.DiscoveredHosts != 8 {
		t.Errorf("completed %d hosts, discovered %d; want 8 of each", len(completed), result.DiscoveredHosts)
	}
	if got := cov.Remaining(); got != "" {
		t.Errorf("a finished scan should leave nothing, got %q", got)
	}
	if !strings.Contains(strings.Join(messages, "\n"), "splitting into 8 blocks") {
		t.Error("the split should be announced in the progress log")
	}
}

// The case resuming exists for: cancelled while block 4 of 8 is still in
// masscan. Blocks 1-3 and their hosts are done and must not be scanned
// again; blocks 4-8 are exactly what is left.
func TestRunScanCancelledMidwayReportsTheRest(t *testing.T) {
	masscan, nmap, _ := writeFakeScanners(t, 4)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1, Concurrency: 2}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	done := 0
	cov := &ScanCoverage{}
	_, _ = RunScan(ctx, cfg, "10.9.0.0/20", "22", Excludes{}, nil, nil, nil, nil,
		func(h HostResult) {
			mu.Lock()
			done++
			if done == 3 {
				cancel()
			}
			mu.Unlock()
		},
		cov,
	)
	if got := cov.Remaining(); got != "10.9.6.0-10.9.15.255" {
		t.Errorf("remaining = %q, want blocks 4-8 (10.9.6.0-10.9.15.255)", got)
	}
}

// A single-pass scan keeps the exact target it was given - the command
// line for anything below the split threshold is unchanged.
func TestRunScanSmallTargetIsOnePassWithTheSpecAsGiven(t *testing.T) {
	masscan, nmap, logPath := writeFakeScanners(t, 0)
	cfg := Config{MasscanPath: masscan, NmapPath: nmap, MasscanRate: 1000, Concurrency: 2}
	if _, err := RunScan(context.Background(), cfg, "10.9.0.0/24", "22", Excludes{}, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if calls := readLines(t, logPath); len(calls) != 1 || calls[0] != "10.9.0.0/24" {
		t.Errorf("masscan calls = %v, want exactly [10.9.0.0/24]", calls)
	}
}
