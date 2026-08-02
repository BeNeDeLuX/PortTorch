package pipeline

import "testing"

func TestParseIPv6TargetList(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    []string
		wantErr bool
	}{
		{"single address", "2001:db8::1", []string{"2001:db8::1"}, false},
		{"comma list", "2001:db8::1,2001:db8::2", []string{"2001:db8::1", "2001:db8::2"}, false},
		{"comma list with spaces", "2001:db8::1, 2001:db8::2 ", []string{"2001:db8::1", "2001:db8::2"}, false},
		{"loopback", "::1", []string{"::1"}, false},
		{"cidr rejected", "2001:db8::/32", nil, true},
		{"range rejected", "2001:db8::1-2001:db8::10", nil, true},
		{"ipv4-mapped rejected as ipv4", "::ffff:192.168.1.1", nil, true},
		{"empty", "", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIPv6TargetList(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseIPv6TargetList(%q) = %v, want an error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIPv6TargetList(%q) returned error: %v", tc.spec, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseIPv6TargetList(%q) = %v, want %v", tc.spec, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("parseIPv6TargetList(%q)[%d] = %q, want %q", tc.spec, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestIsTargetExcluded(t *testing.T) {
	excludes := []string{"2001:db8::1", "2001:db8:1::/64", "10.0.0.0/24"}

	cases := []struct {
		name     string
		ip       string
		excluded bool
	}{
		{"exact match", "2001:db8::1", true},
		{"cidr containment", "2001:db8:1::abcd", true},
		{"outside cidr", "2001:db8:2::abcd", false},
		{"unrelated address, mixed-family list doesn't panic or false-match", "2001:db8::2", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			excluded, _ := isTargetExcluded(tc.ip, excludes)
			if excluded != tc.excluded {
				t.Errorf("isTargetExcluded(%q, %v) = %v, want %v", tc.ip, excludes, excluded, tc.excluded)
			}
		})
	}
}

func TestIsTargetExcludedNoMatch(t *testing.T) {
	excluded, reason := isTargetExcluded("2001:db8::99", []string{"10.0.0.0/24", "192.168.1.1"})
	if excluded {
		t.Errorf("expected no match against a list of only IPv4 entries, got matched via %q", reason)
	}
}
