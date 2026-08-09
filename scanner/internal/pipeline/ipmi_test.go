package pipeline

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestIpmiPortFromNmapRun(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="623">
        <state state="open"/>
        <service name="asf-rmcp"/>
        <script id="ipmi-version" output="Version: IPMI-2.0&#10;UserAuth: NONE_AUTH, MD5, PASSWORD&#10;PassAuth: MD5, PASSWORD&#10;Level: 1.5, 2.0&#10;Unknown1: 899705"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	port := ipmiPortFromNmapRun(&run)
	if port == nil {
		t.Fatal("expected a non-nil PortResult")
	}
	if port.Port != 623 || port.Protocol != "udp" || port.State != "open" || port.ServiceName != "ipmi" {
		t.Errorf("unexpected port fields: %+v", port)
	}
	if len(port.ExtraScripts) != 1 || port.ExtraScripts[0].ID != "ipmi-version" {
		t.Fatalf("expected exactly one ipmi-version extra script, got %+v", port.ExtraScripts)
	}
	if want := "IPMI-2.0"; !strings.Contains(port.ExtraScripts[0].Output, want) {
		t.Errorf("expected output to contain %q, got %q", want, port.ExtraScripts[0].Output)
	}
}

func TestIpmiPortFromNmapRunNoResponse(t *testing.T) {
	// The common case: nothing answered on UDP/623 at all, so nmap
	// reports no ipmi-version script output - must return nil, not a
	// fabricated "open" port for a service that was never actually
	// confirmed present.
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="623">
        <state state="open|filtered"/>
        <service name="asf-rmcp"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	if port := ipmiPortFromNmapRun(&run); port != nil {
		t.Errorf("expected nil when ipmi-version produced no output, got %+v", port)
	}
}

func TestIpmiPortFromNmapRunNoHosts(t *testing.T) {
	if port := ipmiPortFromNmapRun(&nmapRun{}); port != nil {
		t.Errorf("expected nil for an empty nmapRun, got %+v", port)
	}
}
