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
