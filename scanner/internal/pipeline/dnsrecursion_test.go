package pipeline

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestDnsRecursionPortFromNmapRun(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.11" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain"/>
        <script id="dns-recursion" output="Recursion appears to be enabled"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	port := dnsRecursionPortFromNmapRun(&run)
	if port == nil {
		t.Fatal("expected a non-nil PortResult")
	}
	if port.Port != 53 || port.Protocol != "udp" || port.State != "open" || port.ServiceName != "dns" {
		t.Errorf("unexpected port fields: %+v", port)
	}
	if len(port.ExtraScripts) != 1 || port.ExtraScripts[0].ID != "dns-recursion" {
		t.Fatalf("expected exactly one dns-recursion extra script, got %+v", port.ExtraScripts)
	}
	if want := "Recursion appears to be enabled"; !strings.Contains(port.ExtraScripts[0].Output, want) {
		t.Errorf("expected output to contain %q, got %q", want, port.ExtraScripts[0].Output)
	}
}

func TestDnsRecursionPortFromNmapRunNotRecursive(t *testing.T) {
	// The common, well-configured case: the server answered but isn't an
	// open recursive resolver, so dns-recursion produces no output at
	// all - must return nil, not a fabricated "vulnerable" result.
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.11" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	if port := dnsRecursionPortFromNmapRun(&run); port != nil {
		t.Errorf("expected nil when dns-recursion produced no output, got %+v", port)
	}
}

func TestDnsRecursionPortFromNmapRunNoHosts(t *testing.T) {
	if port := dnsRecursionPortFromNmapRun(&nmapRun{}); port != nil {
		t.Errorf("expected nil for an empty nmapRun, got %+v", port)
	}
}
