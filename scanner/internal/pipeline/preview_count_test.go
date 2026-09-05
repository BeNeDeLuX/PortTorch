package pipeline

import "testing"

// The numbers a dry run prints are the whole reason for printing it, so
// each target form masscan accepts is pinned rather than spot-checked.
func TestCountAddresses(t *testing.T) {
	cases := []struct {
		spec string
		want int64
	}{
		{"10.0.0.1", 1},
		{"10.0.0.0/24", 256},
		{"10.0.0.0/32", 1},
		{"10.0.0.0/16", 65536},
		{"10.0.0.1-10.0.0.10", 10},
		// Inclusive at both ends: a range of one address is one address,
		// not zero.
		{"10.0.0.5-10.0.0.5", 1},
		// masscan's grammar takes a comma-separated mixture, and so does
		// this - the sum, not the largest part.
		{"10.0.0.0/24,192.168.1.1,172.16.0.1-172.16.0.4", 256 + 1 + 4},
		{" 10.0.0.0/30 , 10.0.1.1 ", 4 + 1},
		// Not countable without resolving it, so 0 rather than a guess.
		{"scanner.internal", 0},
		{"", 0},
		// A backwards range is malformed, not an empty one.
		{"10.0.0.10-10.0.0.1", 0},
		// IPv6 is counted on the address-list path instead, where
		// excludes can be subtracted exactly.
		{"2001:db8::1", 0},
	}
	for _, c := range cases {
		if got := CountAddresses(c.spec); got != c.want {
			t.Errorf("CountAddresses(%q) = %d, want %d", c.spec, got, c.want)
		}
	}
}

func TestCountPorts(t *testing.T) {
	cases := []struct {
		spec string
		want int
	}{
		{"22", 1},
		{"22,80,443", 3},
		{"1-1000", 1000},
		// Each protocol counts separately: the same port number over TCP
		// and UDP is two probes, which is what a runtime estimate needs.
		{"T:80,U:80", 2},
		{"80,U:53,U:161", 3},
		// Overlapping parts are one port, not two.
		{"80,80", 1},
		{"1-10,5-15", 15},
		{"not a port spec", 0},
	}
	for _, c := range cases {
		if got := CountPorts(c.spec); got != c.want {
			t.Errorf("CountPorts(%q) = %d, want %d", c.spec, got, c.want)
		}
	}
}

// An IPv6 preview enumerates its addresses, so an excluded one is
// genuinely subtracted rather than estimated around.
func TestPreviewCountsIPv6AddressesMinusExcludes(t *testing.T) {
	p, err := PreviewScan("2001:db8::1,2001:db8::2,2001:db8::3", "80", Excludes{IPs: []string{"2001:db8::2"}})
	if err != nil {
		t.Fatalf("PreviewScan: %v", err)
	}
	if p.AddressCount != 2 {
		t.Errorf("AddressCount = %d, want 2 (three listed, one excluded)", p.AddressCount)
	}
}
