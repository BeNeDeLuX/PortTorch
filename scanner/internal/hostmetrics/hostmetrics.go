// Package hostmetrics samples the scanner host's CPU, memory, network
// throughput and load from /proc, for the dashboard's per-scanner charts.
//
// Read straight from /proc rather than through a library: four small
// files, a few lines of parsing each, and no dependency for a feature that
// only ever runs on Linux. Rates (CPU %, bytes per second) need two
// readings, so a Sampler keeps the previous one and its first call only
// primes it.
package hostmetrics

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sample is one minute's worth of the host's state, as sent to the
// webserver.
type Sample struct {
	At            time.Time `json:"at"`
	CPUPercent    float64   `json:"cpuPercent"`
	MemUsedBytes  uint64    `json:"memUsedBytes"`
	MemTotalBytes uint64    `json:"memTotalBytes"`
	NetRxBps      float64   `json:"netRxBytesPerSec"`
	NetTxBps      float64   `json:"netTxBytesPerSec"`
	Load1         float64   `json:"load1"`
	ScansRunning  int       `json:"scansRunning"`
}

type reading struct {
	at       time.Time
	cpuIdle  uint64
	cpuTotal uint64
	netRx    uint64
	netTx    uint64
	memTotal uint64
	memAvail uint64
	load1    float64
}

// Sampler turns successive /proc readings into rates.
type Sampler struct {
	root string
	prev *reading
}

// New samples the real /proc.
func New() *Sampler { return &Sampler{root: "/proc"} }

// NewAt samples a /proc-shaped directory, for tests.
func NewAt(root string) *Sampler { return &Sampler{root: root} }

// Available reports whether this host has a /proc to read at all - false on
// anything that is not Linux, where the reporter simply does not start.
func (s *Sampler) Available() bool {
	_, err := os.Stat(filepath.Join(s.root, "stat"))
	return err == nil
}

// Sample reads /proc and returns the rates since the previous call. ok is
// false on the first call, which only establishes the baseline.
func (s *Sampler) Sample(now time.Time) (Sample, bool, error) {
	r, err := s.read(now)
	if err != nil {
		return Sample{}, false, err
	}
	prev := s.prev
	s.prev = &r
	if prev == nil {
		return Sample{}, false, nil
	}
	secs := r.at.Sub(prev.at).Seconds()
	if secs <= 0 {
		return Sample{}, false, nil
	}
	out := Sample{
		At:            r.at.UTC().Truncate(time.Second),
		MemTotalBytes: r.memTotal,
		Load1:         r.load1,
	}
	if r.memTotal >= r.memAvail {
		out.MemUsedBytes = r.memTotal - r.memAvail
	}
	if total := delta(prev.cpuTotal, r.cpuTotal); total > 0 {
		idle := delta(prev.cpuIdle, r.cpuIdle)
		if idle > total {
			idle = total
		}
		out.CPUPercent = 100 * float64(total-idle) / float64(total)
	}
	out.NetRxBps = float64(delta(prev.netRx, r.netRx)) / secs
	out.NetTxBps = float64(delta(prev.netTx, r.netTx)) / secs
	return out, true, nil
}

// A counter that went backwards was reset (an interface re-created, a
// counter wrapped); the honest delta for that interval is unknown, and 0
// is far less wrong than an enormous spike.
func delta(prev, cur uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func (s *Sampler) read(now time.Time) (reading, error) {
	r := reading{at: now}
	stat, err := os.ReadFile(filepath.Join(s.root, "stat"))
	if err != nil {
		return r, err
	}
	if r.cpuIdle, r.cpuTotal, err = ParseCPU(string(stat)); err != nil {
		return r, err
	}
	mem, err := os.ReadFile(filepath.Join(s.root, "meminfo"))
	if err != nil {
		return r, err
	}
	r.memTotal, r.memAvail = ParseMem(string(mem))
	if net, err := os.ReadFile(filepath.Join(s.root, "net", "dev")); err == nil {
		r.netRx, r.netTx = ParseNetDev(string(net))
	}
	if load, err := os.ReadFile(filepath.Join(s.root, "loadavg")); err == nil {
		r.load1 = ParseLoad(string(load))
	}
	return r, nil
}

// ParseCPU reads the aggregate "cpu" line of /proc/stat. Idle counts
// iowait too - a CPU waiting on disk is not doing work. Total is the first
// eight fields: guest and guest_nice are already included in user and
// nice, and adding them again would double count a VM host's guests.
func ParseCPU(stat string) (idle, total uint64, err error) {
	for _, line := range strings.Split(stat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var v [8]uint64
		for i := 0; i < 8 && i+1 < len(fields); i++ {
			v[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		}
		for _, x := range v {
			total += x
		}
		return v[3] + v[4], total, nil
	}
	return 0, 0, fmt.Errorf("no aggregate cpu line in /proc/stat")
}

// ParseMem returns MemTotal and MemAvailable in bytes. Used memory is
// total minus available - "available" already counts reclaimable cache,
// so a host with a large page cache is not reported as full.
func ParseMem(meminfo string) (total, available uint64) {
	sc := bufio.NewScanner(strings.NewReader(meminfo))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	return total, available
}

// Interfaces whose traffic is not the host's own: loopback, and the
// virtual plumbing of containers and VMs, whose bytes also cross the
// physical interface and would otherwise be counted twice on a Docker or
// libvirt host. A VPN tunnel is kept - its traffic is real.
var virtualPrefixes = []string{"lo", "docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "kube-"}

func isVirtual(name string) bool {
	for _, p := range virtualPrefixes {
		if name == p || strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ParseNetDev sums received and transmitted bytes over the host's real
// interfaces.
func ParseNetDev(dev string) (rx, tx uint64) {
	for _, line := range strings.Split(dev, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || isVirtual(name) {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += r
		tx += t
	}
	return rx, tx
}

// ParseLoad returns the one-minute load average.
func ParseLoad(loadavg string) float64 {
	fields := strings.Fields(loadavg)
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}
