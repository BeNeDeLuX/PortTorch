package pipeline

import "testing"

func TestSubtractPorts(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		excludes []string
		want     string
	}{
		{"no excludes", "22,80,443", nil, "22,80,443"},
		{"exclude single port", "22,80,443", []string{"80"}, "22,443"},
		{"exclude splits a range", "1-100", []string{"50"}, "1-49,51-100"},
		{"exclude whole range", "1-1000", []string{"1-1000"}, ""},
		{"exclude range overlapping edge", "1-100", []string{"90-200"}, "1-89"},
		{"exclude not present", "22,80", []string{"3389"}, "22,80"},
		{"duplicate ports collapse", "22,22,23", nil, "22-23"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := subtractPorts(tc.spec, tc.excludes)
			if err != nil {
				t.Fatalf("subtractPorts(%q, %v) returned error: %v", tc.spec, tc.excludes, err)
			}
			if got != tc.want {
				t.Errorf("subtractPorts(%q, %v) = %q, want %q", tc.spec, tc.excludes, got, tc.want)
			}
		})
	}
}

func TestSubtractPortsInvalid(t *testing.T) {
	if _, err := subtractPorts("not-a-port", nil); err == nil {
		t.Error("expected an error for an invalid port spec, got nil")
	}
	if _, err := subtractPorts("22", []string{"70000"}); err == nil {
		t.Error("expected an error for an out-of-range exclude port, got nil")
	}
}

func TestFilterIPPortExcludes(t *testing.T) {
	discovered := map[string][]PortResult{
		"10.0.0.5": {{Port: 22}, {Port: 3389}},
		"10.0.0.6": {{Port: 3389}},
		"10.0.0.7": {{Port: 80}},
	}

	removed := filterIPPortExcludes(discovered, []IPPortExclude{
		// Only 10.0.0.5's port 3389 is excluded - 10.0.0.6's port 3389
		// must be untouched, since the exclude is scoped to one IP.
		{IP: "10.0.0.5", PortSpec: "3389"},
		// Excludes 10.0.0.7's only port, so the whole host should drop
		// out of the map entirely rather than remain with an empty slice.
		{IP: "10.0.0.7", PortSpec: "80"},
	})

	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if got := discovered["10.0.0.5"]; len(got) != 1 || got[0].Port != 22 {
		t.Errorf("10.0.0.5 ports = %v, want only port 22", got)
	}
	if got := discovered["10.0.0.6"]; len(got) != 1 || got[0].Port != 3389 {
		t.Errorf("10.0.0.6 ports = %v, want untouched port 3389", got)
	}
	if _, ok := discovered["10.0.0.7"]; ok {
		t.Errorf("10.0.0.7 should have been removed entirely, still present: %v", discovered["10.0.0.7"])
	}
}

func TestIsPortExcludedForHost(t *testing.T) {
	excludes := Excludes{
		Ports:   []string{"445", "3389"},
		IPPorts: []IPPortExclude{{IP: "10.0.0.5", PortSpec: "161"}},
	}

	cases := []struct {
		name string
		ip   string
		port int
		want bool
	}{
		{"covered by a global port exclude", "10.0.0.9", 445, true},
		{"covered by an ip+port exclude scoped to this host", "10.0.0.5", 161, true},
		{"same port, but the ip+port exclude is scoped to a different host", "10.0.0.6", 161, false},
		{"not excluded at all", "10.0.0.9", 22, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPortExcludedForHost(c.ip, c.port, excludes); got != c.want {
				t.Errorf("isPortExcludedForHost(%q, %d, ...) = %v, want %v", c.ip, c.port, got, c.want)
			}
		})
	}
}

func TestSubtractPortsPreservesTCPOnlyOutput(t *testing.T) {
	// A spec with no UDP in it must serialize exactly as it always did -
	// no T: prefix appearing on every existing deployment's scans.
	got, err := subtractPorts("22,80,443", []string{"80"})
	if err != nil {
		t.Fatalf("subtractPorts: %v", err)
	}
	if got != "22,443" {
		t.Fatalf("got %q, want 22,443", got)
	}
}

func TestSubtractPortsKeepsProtocolsApart(t *testing.T) {
	got, err := subtractPorts("80,443,U:53,U:161", nil)
	if err != nil {
		t.Fatalf("subtractPorts: %v", err)
	}
	if got != "T:80,443,U:53,161" {
		t.Fatalf("got %q, want T:80,443,U:53,161", got)
	}
}

func TestSubtractPortsExcludeAppliesToBothProtocols(t *testing.T) {
	// A port exclude is protocol-agnostic on purpose: "never touch 53 on
	// this network" has to cover UDP/53 as well, since scan_excludes has
	// no way to express a protocol.
	got, err := subtractPorts("53,80,U:53,U:161", []string{"53"})
	if err != nil {
		t.Fatalf("subtractPorts: %v", err)
	}
	if got != "T:80,U:161" {
		t.Fatalf("got %q, want T:80,U:161 (both TCP/53 and UDP/53 removed)", got)
	}
}

func TestSubtractPortsUDPRangeAndEmptyResult(t *testing.T) {
	got, err := subtractPorts("U:1000-1002", nil)
	if err != nil {
		t.Fatalf("subtractPorts: %v", err)
	}
	if got != "U:1000-1002" {
		t.Fatalf("got %q, want U:1000-1002", got)
	}

	got, err = subtractPorts("U:53", []string{"53"})
	if err != nil {
		t.Fatalf("subtractPorts: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty (nothing left to scan)", got)
	}
}

func TestParseProtoPortSetRejectsAnUnknownPrefix(t *testing.T) {
	if _, err := parseProtoPortSet("S:53"); err == nil {
		t.Fatal("expected an error for an unknown protocol prefix")
	}
}
