package pipeline

import "testing"

func TestHostsFromMasscanRecordsDeduplicatesRetriedPorts(t *testing.T) {
	// --retries resending a probe can make masscan write the same open
	// port as its own top-level JSON record more than once (e.g. both the
	// original probe and a retry got a reply) - this must collapse to one
	// PortResult, not feed nmap's -p list a duplicate port number.
	records := []masscanRecord{
		{IP: "10.0.0.5", Ports: []masscanPortEntry{{Port: 22, Proto: "tcp", Status: "open"}}},
		{IP: "10.0.0.5", Ports: []masscanPortEntry{{Port: 22, Proto: "tcp", Status: "open"}}},
		{IP: "10.0.0.5", Ports: []masscanPortEntry{{Port: 80, Proto: "tcp", Status: "open"}}},
	}

	hosts := hostsFromMasscanRecords(records)

	ports, ok := hosts["10.0.0.5"]
	if !ok {
		t.Fatalf("expected an entry for 10.0.0.5, got %+v", hosts)
	}
	if len(ports) != 2 {
		t.Fatalf("expected exactly 2 deduplicated ports, got %d: %+v", len(ports), ports)
	}
}

func TestHostsFromMasscanRecordsDifferentProtocolsNotCollapsed(t *testing.T) {
	// Same port number, different protocol, on the same host - must stay
	// as two distinct results, not collide in the dedup key.
	records := []masscanRecord{
		{IP: "10.0.0.9", Ports: []masscanPortEntry{{Port: 161, Proto: "udp", Status: "open"}}},
		{IP: "10.0.0.9", Ports: []masscanPortEntry{{Port: 161, Proto: "tcp", Status: "open"}}},
	}

	hosts := hostsFromMasscanRecords(records)

	if len(hosts["10.0.0.9"]) != 2 {
		t.Fatalf("expected 2 distinct ports (different protocols), got %+v", hosts["10.0.0.9"])
	}
}

func TestHostsFromMasscanRecordsMultipleHosts(t *testing.T) {
	records := []masscanRecord{
		{IP: "10.0.0.5", Ports: []masscanPortEntry{{Port: 22, Proto: "tcp", Status: "open"}}},
		{IP: "10.0.0.6", Ports: []masscanPortEntry{{Port: 22, Proto: "tcp", Status: "open"}}},
	}

	hosts := hostsFromMasscanRecords(records)

	if len(hosts) != 2 {
		t.Fatalf("expected 2 distinct hosts, got %+v", hosts)
	}
	if len(hosts["10.0.0.5"]) != 1 || len(hosts["10.0.0.6"]) != 1 {
		t.Fatalf("expected 1 port each, got %+v", hosts)
	}
}

func TestHostsFromMasscanRecordsEmpty(t *testing.T) {
	if hosts := hostsFromMasscanRecords(nil); len(hosts) != 0 {
		t.Errorf("expected empty map for nil records, got %+v", hosts)
	}
}
