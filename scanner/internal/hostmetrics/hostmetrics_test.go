package hostmetrics

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Captured from a real Debian 13 host, so the parsers are checked against
// the format the kernel actually writes rather than one remembered.
const realStat = `cpu  4195942 56 1449099 210002259 2281023 0 212342 43586 0 0
cpu0 2098195 29 725202 105017214 1138349 0 98589 21621 0 0
cpu1 2097746 27 723897 104985045 1142674 0 113752 21964 0 0
ctxt 1359759863
`

const realMeminfo = `MemTotal:        8138552 kB
MemFree:          512000 kB
MemAvailable:    6695184 kB
Buffers:          100000 kB
`

const realNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 2163904493 5406195    0    0    0     0          0         0 2163904493 5406195    0    0    0     0       0          0
 ens18: 8596529676 17016672    0    1    0     0          0         0 3657955061 23494196    0    0    0     0       0          0
docker0: 1498903   18621    0    0    0     0          0         0 124252584   31130    0   24    0     0       0          0
br-c81289c892a3:       0       0    0    0    0     0          0         0        0       0    0   19    0     0       0          0
vethab12: 5000   10    0    0    0     0          0         0 6000   10    0    0    0     0       0          0
  wg0: 1000   5    0    0    0     0          0         0 2000   5    0    0    0     0       0          0
`

func TestParsersReadTheRealFormats(t *testing.T) {
	idle, total, err := ParseCPU(realStat)
	if err != nil {
		t.Fatal(err)
	}
	if idle != 210002259+2281023 {
		t.Errorf("idle = %d, want idle+iowait", idle)
	}
	if total != 4195942+56+1449099+210002259+2281023+0+212342+43586 {
		t.Errorf("total = %d, want the first eight fields", total)
	}

	memTotal, avail := ParseMem(realMeminfo)
	if memTotal != 8138552*1024 || avail != 6695184*1024 {
		t.Errorf("mem = %d/%d", memTotal, avail)
	}

	// ens18 and the WireGuard tunnel count; loopback, the docker bridge,
	// the compose network and the container's veth do not.
	rx, tx := ParseNetDev(realNetDev)
	if rx != 8596529676+1000 || tx != 3657955061+2000 {
		t.Errorf("net = %d/%d", rx, tx)
	}

	if ParseLoad("0.08 0.13 0.11 1/271 2632475") != 0.08 {
		t.Error("load1")
	}
}

func writeProc(t *testing.T, dir, stat, meminfo, netdev string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"stat": stat, "meminfo": meminfo, "net/dev": netdev, "loadavg": "1.50 1.00 0.50 1/100 1\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func netdev(rx, tx int) string {
	return "Inter-|\n face |\n  eth0: " + strconv.Itoa(rx) + " 0 0 0 0 0 0 0 " + strconv.Itoa(tx) + " 0 0 0 0 0 0 0\n"
}

func TestSamplerTurnsReadingsIntoRates(t *testing.T) {
	dir := t.TempDir()
	s := NewAt(dir)
	writeProc(t, dir, "cpu  100 0 100 800 0 0 0 0 0 0\n", "MemTotal: 1000 kB\nMemAvailable: 250 kB\n", netdev(1000, 500))
	t0 := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if _, ok, err := s.Sample(t0); ok || err != nil {
		t.Fatalf("first sample should only prime: ok=%v err=%v", ok, err)
	}

	// 60 seconds later: 400 more jiffies of which 100 idle (75% busy),
	// 60 KB/s received and 30 KB/s sent.
	writeProc(t, dir, "cpu  250 0 250 900 0 0 0 0 0 0\n", "MemTotal: 1000 kB\nMemAvailable: 250 kB\n", netdev(1000+60*1024*60, 500+30*1024*60))
	got, ok, err := s.Sample(t0.Add(60 * time.Second))
	if !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if math.Abs(got.CPUPercent-75) > 0.001 {
		t.Errorf("cpu = %v, want 75", got.CPUPercent)
	}
	if got.MemUsedBytes != 750*1024 || got.MemTotalBytes != 1000*1024 {
		t.Errorf("mem = %d/%d", got.MemUsedBytes, got.MemTotalBytes)
	}
	if math.Abs(got.NetRxBps-60*1024) > 0.001 || math.Abs(got.NetTxBps-30*1024) > 0.001 {
		t.Errorf("net = %v/%v", got.NetRxBps, got.NetTxBps)
	}
	if got.Load1 != 1.5 {
		t.Errorf("load = %v", got.Load1)
	}
}

func TestACounterThatWentBackwardsIsNotASpike(t *testing.T) {
	dir := t.TempDir()
	s := NewAt(dir)
	writeProc(t, dir, "cpu  100 0 100 800 0 0 0 0 0 0\n", "MemTotal: 1000 kB\nMemAvailable: 500 kB\n", netdev(5_000_000, 5_000_000))
	t0 := time.Now()
	s.Sample(t0)
	// The interface was re-created and its counters restarted.
	writeProc(t, dir, "cpu  200 0 200 900 0 0 0 0 0 0\n", "MemTotal: 1000 kB\nMemAvailable: 500 kB\n", netdev(1000, 1000))
	got, ok, _ := s.Sample(t0.Add(time.Minute))
	if !ok || got.NetRxBps != 0 || got.NetTxBps != 0 {
		t.Errorf("reset counters should read as 0, got %+v", got)
	}
}
