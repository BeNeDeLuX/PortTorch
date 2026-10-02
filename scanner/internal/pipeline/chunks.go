package pipeline

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"porttorch/scanner/internal/progress"
)

// A large IPv4 target is discovered in blocks rather than in one masscan
// pass. masscan reports nothing until its whole pass finishes, so a /16
// across a real port list used to be hours of silence before nmap saw a
// single host, and cancelling it threw away everything masscan had
// already probed. Per block, results start flowing after the first block,
// and a cancelled scan knows exactly which blocks it finished - which is
// what makes resuming it possible at all (see ScanCoverage).
//
// Only addresses are split, never ports, for two reasons that both rule
// the port axis out rather than merely disfavour it:
//   - a host's submission is its whole result for this scan, and the
//     webserver infers "port closed" from a port that is inside the
//     scan's requested spec but absent from that submission. A host
//     reported once per port block would close, in the webserver's view,
//     every port found in the other blocks.
//   - masscan's rate is a total. Fewer addresses per pass means more
//     packets per address, so the block floor is a /24's worth of
//     addresses: never more concentrated than scanning one /24 today.
//
// That floor is also why a small range with a huge port list is not split:
// a /24 across 1-65535 stays one pass, exactly as before.
const (
	chunkMinAddresses = 256
	// Aim for blocks that take about this long, so results arrive a few
	// minutes apart rather than every few seconds (each masscan run also
	// waits ~10s for late replies after sending, which tiny blocks would
	// multiply) or every few hours.
	chunkTargetDuration = 5 * time.Minute
	// Below this total, a single pass is short enough that splitting buys
	// nothing, and the command line stays byte-identical to what every
	// earlier version ran.
	chunkThreshold = 10 * time.Minute
)

type ipv4Range struct {
	start, end uint32
}

func (r ipv4Range) size() uint64 { return uint64(r.end) - uint64(r.start) + 1 }

// parseIPv4Ranges reads a comma-separated spec of IPv4 addresses, CIDRs and
// start-end ranges. ok is false if any part is something else (a hostname,
// IPv6, junk) - the caller then leaves the spec to masscan untouched rather
// than planning around a guess.
func parseIPv4Ranges(spec string) ([]ipv4Range, bool) {
	var out []ipv4Range
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, ok := parseIPv4Part(part)
		if !ok {
			return nil, false
		}
		out = append(out, r)
	}
	return out, len(out) > 0
}

func parseIPv4Part(part string) (ipv4Range, bool) {
	if strings.Contains(part, "/") {
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil || ipnet.IP.To4() == nil {
			return ipv4Range{}, false
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return ipv4Range{}, false
		}
		start := ipToUint32(ipnet.IP.To4())
		end := start | uint32((uint64(1)<<uint(32-ones))-1)
		return ipv4Range{start, end}, true
	}
	if before, after, found := strings.Cut(part, "-"); found {
		s, e := net.ParseIP(strings.TrimSpace(before)), net.ParseIP(strings.TrimSpace(after))
		if s == nil || e == nil || s.To4() == nil || e.To4() == nil {
			return ipv4Range{}, false
		}
		a, b := ipToUint32(s.To4()), ipToUint32(e.To4())
		if b < a {
			return ipv4Range{}, false
		}
		return ipv4Range{a, b}, true
	}
	ip := net.ParseIP(part)
	if ip == nil || ip.To4() == nil {
		return ipv4Range{}, false
	}
	v := ipToUint32(ip.To4())
	return ipv4Range{v, v}, true
}

// mergeRanges sorts and coalesces overlapping or adjacent ranges.
func mergeRanges(in []ipv4Range) []ipv4Range {
	if len(in) == 0 {
		return nil
	}
	rs := append([]ipv4Range(nil), in...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	out := []ipv4Range{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if uint64(r.start) <= uint64(last.end)+1 {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// subtractRanges removes every address in excl from targets. Both inputs
// are merged first, so the result is sorted and non-overlapping.
func subtractRanges(targets, excl []ipv4Range) []ipv4Range {
	targets, excl = mergeRanges(targets), mergeRanges(excl)
	var out []ipv4Range
	for _, t := range targets {
		cur := uint64(t.start)
		end := uint64(t.end)
		for _, x := range excl {
			if uint64(x.end) < cur || uint64(x.start) > end {
				continue
			}
			if uint64(x.start) > cur {
				out = append(out, ipv4Range{uint32(cur), x.start - 1})
			}
			cur = uint64(x.end) + 1
			if cur > end {
				break
			}
		}
		if cur <= end {
			out = append(out, ipv4Range{uint32(cur), uint32(end)})
		}
	}
	return out
}

func uint32ToIP(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// formatRanges renders ranges in the target grammar masscan and the
// webserver both accept: a bare address, or "start-end".
func formatRanges(rs []ipv4Range) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.start == r.end {
			parts = append(parts, uint32ToIP(r.start))
		} else {
			parts = append(parts, uint32ToIP(r.start)+"-"+uint32ToIP(r.end))
		}
	}
	return strings.Join(parts, ",")
}

// chunkPlan is how a target will be discovered: one or more blocks, each a
// masscan target spec in its own right.
type chunkPlan struct {
	blocks    [][]ipv4Range
	addresses uint64
	perBlock  uint64
	estimate  time.Duration
}

// planIPv4Chunks decides whether to split, and how. It returns nil - one
// pass with the spec exactly as given - unless the target is plain IPv4,
// larger than one block, and estimated to take longer than chunkThreshold.
//
// IP excludes are subtracted before planning so a block is never spent on
// addresses masscan would skip anyway, and so a fully excluded block
// simply does not exist. masscan still gets --excludefile for every block,
// which keeps it the enforcement point exactly as before; this is only
// planning.
func planIPv4Chunks(spec string, excludeIPs []string, portCount, rate int) *chunkPlan {
	if portCount <= 0 || rate <= 0 {
		return nil
	}
	targets, ok := parseIPv4Ranges(spec)
	if !ok {
		return nil
	}
	var excl []ipv4Range
	for _, e := range excludeIPs {
		if r, ok := parseIPv4Part(strings.TrimSpace(e)); ok {
			excl = append(excl, r)
		}
	}
	effective := subtractRanges(targets, excl)

	var addresses uint64
	for _, r := range effective {
		addresses += r.size()
	}
	if addresses <= chunkMinAddresses {
		return nil
	}
	estimate := time.Duration(float64(addresses) * float64(portCount) / float64(rate) * float64(time.Second))
	if estimate <= chunkThreshold {
		return nil
	}

	per := uint64(float64(rate) * chunkTargetDuration.Seconds() / float64(portCount))
	if per < chunkMinAddresses {
		per = chunkMinAddresses
	}
	per = (per + chunkMinAddresses - 1) / chunkMinAddresses * chunkMinAddresses
	if per >= addresses {
		return nil
	}

	plan := &chunkPlan{addresses: addresses, perBlock: per, estimate: estimate}
	var block []ipv4Range
	var inBlock uint64
	for _, r := range effective {
		cur := uint64(r.start)
		for cur <= uint64(r.end) {
			take := per - inBlock
			if left := uint64(r.end) - cur + 1; left < take {
				take = left
			}
			block = append(block, ipv4Range{uint32(cur), uint32(cur + take - 1)})
			inBlock += take
			cur += take
			if inBlock == per {
				plan.blocks = append(plan.blocks, block)
				block, inBlock = nil, 0
			}
		}
	}
	if len(block) > 0 {
		plan.blocks = append(plan.blocks, block)
	}
	return plan
}

// truncateForLog keeps a block's spec readable in a progress line - a
// sparse target can make one block a long list of small ranges.
func truncateForLog(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (p *chunkPlan) describe(portCount, rate int) string {
	return fmt.Sprintf(
		"large target (%d addresses x %d port(s) at %d pps, ~%s): splitting into %d blocks of up to %d addresses so results stream as each block finishes",
		p.addresses, portCount, rate, p.estimate.Round(time.Minute), len(p.blocks), p.perBlock,
	)
}

// ScanCoverage records how much of a scan's target was actually finished,
// so a scan that stopped early - cancelled, or failed partway - can be
// resumed by queueing only what is left. Pass one to RunScan and read
// Remaining after it returns; it is safe for RunScan's goroutines to
// update concurrently.
//
// "Finished" is judged at two levels, and both are needed. A discovery
// block is covered once masscan (or nmap's IPv6 discovery) has completed
// it: every address in it either turned up with open ports or definitely
// did not. A discovered host is covered only once its full result was
// handed on while the scan was still running - a host completing after
// cancellation may have had its screenshot or certificate probe cut
// short, so it is scanned again rather than left with a partial record.
// A host whose nmap call failed never completes, and is likewise left.
type ScanCoverage struct {
	mu        sync.Mutex
	planned   bool
	original  string
	hostnames map[string]string
	blocks    []coverageBlock
	pending   map[string]bool

	// Running totals for the dashboard's progress bar (see Counts).
	blocksDone int
	discovered int
	processed  int
}

// ScanCounts is how far a scan has got, in hosts rather than ports: the
// one unit an operator can reason about, and the only one known in
// advance - discovery says how many hosts nmap will have to enrich, while
// how long each one takes depends on what it turns out to run.
type ScanCounts struct {
	// False until discovery has been planned; nothing below means
	// anything before that.
	Planned bool
	// Discovery passes in total and finished. One for an ordinary scan;
	// more when a large target is discovered in blocks, in which case
	// HostsDiscovered keeps growing until the last block is done.
	DiscoveryBlocks     int
	DiscoveryBlocksDone int
	// Hosts discovery turned up, and how many of those have been dealt
	// with - completed, or given up on because nmap failed for them. A
	// failure counts as processed so the bar can reach its end; the host
	// is still left in Remaining for a resume.
	HostsDiscovered int
	HostsProcessed  int
}

func (c *ScanCoverage) Counts() ScanCounts {
	if c == nil {
		return ScanCounts{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return ScanCounts{
		Planned:             c.planned,
		DiscoveryBlocks:     len(c.blocks),
		DiscoveryBlocksDone: c.blocksDone,
		HostsDiscovered:     c.discovered,
		HostsProcessed:      c.processed,
	}
}

// ProgressCounts adapts Counts to what progress.Tracker.SetCounts takes,
// so every entry point wires the progress bar up with the same one line.
// nil until discovery has been planned - there is nothing to show then.
func (c *ScanCoverage) ProgressCounts() *progress.Counts {
	counts := c.Counts()
	if !counts.Planned {
		return nil
	}
	return &progress.Counts{
		DiscoveryBlocks:     counts.DiscoveryBlocks,
		DiscoveryBlocksDone: counts.DiscoveryBlocksDone,
		HostsDiscovered:     counts.HostsDiscovered,
		HostsProcessed:      counts.HostsProcessed,
	}
}

func (c *ScanCoverage) hostProcessed() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processed++
}

type coverageBlock struct {
	ranges []ipv4Range
	done   bool
}

// plan records the discovery blocks. A single block is the whole target
// as typed, and is reported back verbatim if it never completes - that
// keeps a hostname, an IPv6 list, or any spec this package does not parse
// intact for the resume.
func (c *ScanCoverage) plan(original string, hostnames map[string]string, blocks [][]ipv4Range) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.planned = true
	c.original = original
	c.hostnames = hostnames
	c.pending = make(map[string]bool)
	if len(blocks) == 0 {
		c.blocks = []coverageBlock{{}}
		return
	}
	c.blocks = make([]coverageBlock, len(blocks))
	for i, b := range blocks {
		c.blocks[i] = coverageBlock{ranges: b}
	}
}

func (c *ScanCoverage) blockDiscovered(i int, ips []string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocks[i].done = true
	c.blocksDone++
	c.discovered += len(ips)
	for _, ip := range ips {
		c.pending[ip] = true
	}
}

func (c *ScanCoverage) hostDone(ip string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, ip)
}

// Remaining is the part of the target still to scan, in the same target
// grammar the scan was given, or "" when nothing is left - or when the
// scan stopped before discovery was even planned, in which case nothing
// was covered and re-running the original target is simply a rescan.
func (c *ScanCoverage) Remaining() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.planned {
		return ""
	}
	if len(c.blocks) == 1 && !c.blocks[0].done {
		return c.original
	}

	var ranges []ipv4Range
	for _, b := range c.blocks {
		if !b.done {
			ranges = append(ranges, b.ranges...)
		}
	}
	var others []string
	for ip := range c.pending {
		if name, ok := c.hostnames[ip]; ok {
			others = append(others, name)
			continue
		}
		if r, ok := parseIPv4Part(ip); ok {
			ranges = append(ranges, r)
			continue
		}
		others = append(others, ip)
	}
	sort.Strings(others)

	parts := make([]string, 0, 2)
	if s := formatRanges(mergeRanges(ranges)); s != "" {
		parts = append(parts, s)
	}
	if len(others) > 0 {
		parts = append(parts, strings.Join(others, ","))
	}
	return strings.Join(parts, ",")
}
